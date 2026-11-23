"""Ren'Py-плагин: индекс игры + карта .rpa-архива + детект скомпилированных .rpyc.

Формат RPA-3.0:
  заголовок  "RPA-3.0 " + hex(offset индекса, 8) + " " + hex(key, 8) + "\n"
  индекс     zlib-сжатая строка:
             offset ^ key, length ^ key, b" " + имя файла + b"\n"
             (RPA-3.2: ещё префикс hex-ключа на файл)
"""
from __future__ import annotations

import re
import zlib
from pathlib import Path

from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin
from ...core.util import classify, head_bytes, human_int, iter_files, rel_posix, safe_rel, sha256_file, sniff_magic
from .._shared import copy_verbatim, merge_summaries

RPA_HEADER_RX = re.compile(rb"RPA-(\d\.\d) ([0-9a-f]{8,16}) ([0-9a-f]{8,16})\n")


class RenPyPlugin(EnginePlugin):
    slug = "renpy"
    display_name = "Ren'Py"
    can_extract = True
    notes = ".rpa-архивы (карта + извлечение), индекс .rpyc/.rpy, опционально UnRen."

    # ------------------------------------------------------------------
    def detect(self, root: Path) -> tuple[float, list[str]]:
        score = 0.0
        evidence: list[str] = []
        rpa = rpyc = rpy = other = 0
        for p in iter_files(root):
            name = p.name.lower()
            ext = p.suffix.lower()
            if name == "renpy" or name.startswith("renpy"):
                other += 1
            elif ext == ".live" or ext == ".vbs":  # UnRen следы
                pass
            if ext == ".rpa":
                rpa += 1
                evidence.append(f"архив: {p.name}")
            elif ext == ".rpyc":
                rpyc += 1
            elif ext in (".rpy", ".rpym"):
                rpy += 1
            head = head_bytes(p, 8)
            if head.startswith(b"RPA-") and ext != ".rpa":
                rpa += 1
            if score > 0.95:
                break
        if rpa:
            score += min(0.7, 0.35 * rpa)
        if rpyc or rpy:
            score += min(0.4, 0.02 * (rpyc + rpy))
            evidence.append(f"{rpyc} .rpyc, {rpy} .rpy")
        if other:
            score += 0.1
        return min(score, 0.98), evidence[:8]

    # ------------------------------------------------------------------
    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        root_r = root.resolve()
        archives: list[Path] = []
        for p in iter_files(root, exclude=ctx.exclude):
            rel = rel_posix(p, root_r)
            try:
                size = p.stat().st_size
            except OSError:
                continue
            magic = sniff_magic(head_bytes(p, 16), rel)
            kind = classify(rel, magic)
            if magic in ("renpy_rpa2", "renpy_rpa3"):
                kind = "archive"
            sha = sha256_file(p) if (ctx.hash_files and size <= ctx.hash_limit_mb << 20) else None
            a = ds.add_asset(rel, kind=kind, size=size, sha256=sha)
            if magic:
                a.extra["magic"] = magic
            if magic and magic.startswith("renpy_rpa") or rel.lower().endswith(".rpa"):
                archives.append(p)

        for p in archives:
            self._scan_rpa(ds, p, root_r, ctx)

        if not ds.meta.get("rpa"):
            ds.add_finding("info", "renpy_no_archives",
                           "RPA-архивов нет — игра поставляется распакованной (game/)")
        else:
            ds.add_finding("info", "renpy_archives",
                           f"RPA-архивов: {len(ds.meta['rpa'])}")
        return ds

    # ------------------------------------------------------------------
    def _scan_rpa(self, ds: Dataset, path: Path, root_r: Path, ctx: EngineContext) -> None:
        rel = rel_posix(path, root_r)
        try:
            with open(path, "rb") as f:
                header = f.readline(64)
                m = RPA_HEADER_RX.match(header)
                if not m:
                    ds.add_finding("warn", "rpa_bad_header",
                                   f"{rel}: не RPA 3.x (RPA-2.0 не поддерживается)", path=rel)
                    return
                version = m.group(1).decode()
                index_offset = int(m.group(2), 16)
                key = int(m.group(3), 16)
                f.seek(index_offset)
                raw = zlib.decompress(f.read())
                entries = _parse_rpa3_index(raw, key, version == "3.2")
                ds.meta.setdefault("rpa", []).append(
                    {"file": rel, "version": version, "entries": len(entries)})
                ds.add_finding("info", "rpa_map",
                               f"{rel}: RPA-{version}, файлов {human_int(len(entries))}",
                               "Имена и смещения прочитаны, извлечение — при extract.", path=rel)
                for name, ofs, length in entries:
                    kind = classify(name)
                    a = ds.add_asset(name, kind=kind, size=length, container=rel,
                                     rpa_offset=ofs, rpa_length=length)
                    a.extra.setdefault("tags", []).append("rpa-entry")
        except (OSError, zlib.error, ValueError) as exc:
            ds.add_finding("error", "rpa_error", f"{rel}: {exc}", path=rel)

    # ------------------------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        base = copy_verbatim(dataset, dest, ctx, only_kinds, skip_kinds={"archive"})
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        by_container: dict[str, list] = {}
        for a in dataset.assets:
            if a.container:
                by_container.setdefault(a.container, []).append(a)
        for container, assets in by_container.items():
            src = dataset.root / container
            if not src.is_file():
                out["errors"] += 1
                continue
            stem = Path(container).stem
            try:
                with open(src, "rb") as f:
                    for a in assets:
                        if only_kinds and a.kind not in only_kinds:
                            out["skipped"] += 1
                            continue
                        ofs = a.extra.get("rpa_offset")
                        length = a.extra.get("rpa_length") or 0
                        if ofs is None:
                            out["skipped"] += 1
                            continue
                        f.seek(ofs)
                        data = f.read(min(length, ctx.max_asset_bytes))
                        target = Path(dest) / "rpa" / stem / safe_rel(a.path)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
                        out["extracted"] += 1
                        if len(out["samples"]) < 10:
                            out["samples"].append(a.path)
            except OSError as exc:
                out["errors"] += 1
                out["samples"].append(f"! {container}: {exc}")
        if out["extracted"]:
            out["message"] = f"RPA: извлечено {out['extracted']} файлов."
        return merge_summaries(base, out)


def _parse_rpa3_index(raw: bytes, key: int, rpa32: bool) -> list[tuple[str, int, int]]:
    out: list[tuple[str, int, int]] = []
    for line in raw.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        parts = line.split(b" ", 2)
        if len(parts) < 3:
            continue
        try:
            ofs = int(parts[0], 16) ^ key
            length = int(parts[1], 16) ^ key
        except ValueError:
            continue
        name = parts[2]
        prefix = b""
        if rpa32:
            # в 3.2 имя может начинаться с hex-префикса (ключ файла) и пробела
            sp = name.find(b" ")
            if sp > 0 and all(c in b"0123456789abcdef" for c in name[:sp]):
                prefix = name[:sp]
                name = name[sp + 1:]
        try:
            out.append((name.decode("utf-8"), ofs, length))
        except UnicodeDecodeError:
            continue
    return out
