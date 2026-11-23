"""Godot-плагин: индекс проекта + разбор PCK (GDPC), зависимости .tscn/.import."""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin
from ...core.util import (classify, head_bytes, human_int, iter_files, rel_posix,
                          safe_rel, sha256_file, sniff_magic, ext_of)
from .._shared import copy_verbatim, merge_summaries

GD_EXT = {".tscn", ".tres", ".gd", ".gdc", ".godot", ".import", ".remap",
          ".gde", ".escn", ".scn", ".res", ".pck", ".so", ".dll"}
RES_PATH_RX = __import__("re").compile(r'path="res://([^"]+)"')
RES_UID_RX = __import__("re").compile(r'uid="(uid://[a-z0-9]+)"')


class GodotPlugin(EnginePlugin):
    slug = "godot"
    display_name = "Godot"
    can_extract = True
    notes = "PCK (GDPC v1/v2), .tscn/.tres-зависимости, индекс проекта."

    # ------------------------------------------------------------------
    def detect(self, root: Path) -> tuple[float, list[str]]:
        score = 0.0
        evidence: list[str] = []
        pck = proj = import_files = engine_files = 0
        for p in iter_files(root):
            name = p.name.lower()
            ext = p.suffix.lower()
            if ext == ".pck":
                pck += 1
            elif name == "project.godot":
                proj += 1
                evidence.append(f"project.godot: {rel_posix(p, root) if root in p.parents else p.name}")
            elif ext in (".tscn", ".tres", ".import"):
                import_files += 1
            elif ext in (".gd", ".gdshader") or name.endswith(".godot"):
                engine_files += 1
            head = b""
            if ext in (".exe", ".x86_64", ".x64", "") and not head:
                head = head_bytes(p, 4)
            if score > 0.95:
                break
        if pck:
            score += min(0.7, 0.35 * pck)
            evidence.append(f"{pck} файлов .pck")
        if proj:
            score += 0.35
        if import_files:
            score += min(0.35, 0.02 * import_files)
            evidence.append(f"{import_files} файлов .tscn/.tres/.import")
        if engine_files:
            score += min(0.2, 0.01 * engine_files)
        # .exe со встроенным PCK
        return min(score, 0.98), evidence[:8]

    # ------------------------------------------------------------------
    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        root_r = root.resolve()
        pcks: list[Path] = []
        text_scenes: list[Path] = []
        for p in iter_files(root, exclude=ctx.exclude):
            rel = rel_posix(p, root_r)
            try:
                size = p.stat().st_size
            except OSError:
                continue
            magic = sniff_magic(head_bytes(p, 16), rel)
            kind = classify(rel, magic)
            sha = sha256_file(p) if (ctx.hash_files and size <= ctx.hash_limit_mb << 20) else None
            a = ds.add_asset(rel, kind=kind, size=size, sha256=sha)
            if magic:
                a.extra["magic"] = magic
            low = rel.lower()
            if magic == "godot_pck":
                pcks.append(p)
            elif low.endswith(".pck"):
                a.extra["pck_unrecognized"] = True
                pcks.append(p)
            elif low.endswith((".tscn", ".tres")):
                text_scenes.append(p)
            elif low.endswith("project.godot"):
                self._read_project(ds, p, rel)

        for p in pcks:
            self._scan_pck(ds, p, root_r, ctx)

        if ctx.deep:
            self._scan_deps(ds, text_scenes, root_r)
        return ds

    # ------------------------------------------------------------------
    def _read_project(self, ds: Dataset, path: Path, rel: str) -> None:
        try:
            text = path.read_text("utf-8", errors="ignore")
        except OSError:
            return
        version = None
        name = None
        for line in text.splitlines():
            s = line.strip()
            if s.startswith("config/features="):
                version = s.split("=", 1)[1][:120]
            elif s.startswith("config/name="):
                name = s.split("=", 1)[1].strip('"')
        ds.meta["project"] = {"file": rel, "name": name, "features": version}

    # ------------------------------------------------------------------
    def _scan_pck(self, ds: Dataset, path: Path, root_r: Path, ctx: EngineContext) -> None:
        rel = rel_posix(path, root_r)
        try:
            size = path.stat().st_size
        except OSError:
            return
        try:
            with open(path, "rb") as f:
                base = 0
                head = f.read(4)
                if head != b"GDPC" and size > (4 << 20):
                    # PCK, встроенный в exe: ищем магию в хвосте
                    f.seek(max(0, size - (4 << 20)))
                    tail = f.read()
                    idx = tail.rfind(b"GDPC")
                    if idx < 0:
                        ds.add_finding("warn", "godot_pck_trailer_missing",
                                       f"В {rel} нет магии GDPC", path=rel)
                        return
                    base = size - (4 << 20) + idx
                    f.seek(base)
                    head = f.read(4)
                if head != b"GDPC":
                    ds.add_finding("warn", "godot_pck_unrecognized",
                                   f"{rel}: не PCK или повреждён", path=rel)
                    return
                pack_ver = struct.unpack("<I", f.read(4))[0]
                v = struct.unpack("<III", f.read(12))
                if pack_ver >= 2:
                    flags = struct.unpack("<I", f.read(4))[0]
                    file_base = struct.unpack("<Q", f.read(8))[0]
                else:
                    flags, file_base = 0, 0
                f.read(16 * 4)  # reserved
                if pack_ver >= 2 and (flags & 1):
                    ds.add_finding(
                        "warn", "godot_pck_encrypted",
                        f"{rel}: таблица PCK зашифрована",
                        "Нужен ключ шифрования из ресурсов игры — без него содержимое не перечислить.",
                        path=rel)
                    ds.meta.setdefault("pck", []).append(
                        {"file": rel, "version": f"{v[0]}.{v[1]}.{v[2]}", "encrypted": True})
                    return
                count = struct.unpack("<I", f.read(4))[0]
                if count > 200_000:
                    ds.add_finding("warn", "godot_pck_count",
                                   f"{rel}: подозрительное число файлов ({count})", path=rel)
                    return
                entries = []
                for _ in range(count):
                    plen_raw = f.read(4)
                    if len(plen_raw) < 4:
                        break
                    plen = struct.unpack("<I", plen_raw)[0]
                    raw = f.read(plen)
                    name = raw.rstrip(b"\x00").decode("utf-8", "replace").replace("\\", "/")
                    if name.startswith("res://"):
                        name = name[6:]
                    ofs, fsize = struct.unpack("<QQ", f.read(16))
                    f.read(16)  # md5
                    if pack_ver >= 2 and (flags & 2):
                        abs_ofs = base + ofs
                    elif pack_ver < 2:
                        abs_ofs = ofs  # v1: абсолютные смещения от начала файла
                        if base and ofs < base:  # встроенный pck v1
                            abs_ofs = base + ofs
                    else:
                        abs_ofs = ofs
                    entries.append((name, abs_ofs, fsize))
                ds.meta.setdefault("pck", []).append({
                    "file": rel, "version": f"{v[0]}.{v[1]}.{v[2]}",
                    "entries": len(entries), "encrypted": False,
                })
                ds.add_finding("info", "godot_pck",
                               f"{rel}: PCK v{pack_ver} Godot {v[0]}.{v[1]}.{v[2]}, "
                               f"файлов внутри: {human_int(len(entries))}", path=rel)
                for name, ofs, fsize in entries:
                    if not name or name.endswith("/"):
                        continue
                    kind = classify(name)
                    a = ds.add_asset(name, kind=kind, size=fsize, container=rel,
                                     pck_offset=ofs, pck_stored_size=fsize)
                    a.extra.setdefault("tags", []).append("pck-entry")
        except (OSError, struct.error) as exc:
            ds.add_finding("error", "godot_pck_error",
                           f"{rel}: ошибка чтения PCK — {exc}", path=rel)
        return

    # ------------------------------------------------------------------
    def _scan_deps(self, ds: Dataset, scenes: list[Path], root_r: Path) -> None:
        checked = 0
        for p in scenes:
            if checked >= 3000:
                break
            checked += 1
            try:
                text = p.read_text("utf-8", errors="ignore")
            except OSError:
                continue
            rel = rel_posix(p, root_r)
            for m in RES_PATH_RX.finditer(text):
                ds.add_dep(rel, m.group(1))
            if rel.lower().endswith(".import"):
                for line in text.splitlines():
                    if line.strip().startswith("source_file="):
                        val = line.split("=", 1)[1].strip().strip('"')
                        if val.startswith("res://"):
                            ds.add_dep(rel, val[6:])

    # ------------------------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        base = copy_verbatim(dataset, dest, ctx, only_kinds, skip_kinds={"archive"})
        pck_summary = self._extract_pck_entries(dataset, Path(dest) / "pck", ctx, only_kinds)
        return merge_summaries(base, pck_summary)

    def _extract_pck_entries(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                             only_kinds: set[str] | None) -> dict:
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        root = dataset.root
        by_container: dict[str, list] = {}
        for a in dataset.assets:
            if a.container:
                by_container.setdefault(a.container, []).append(a)
        for container, assets in by_container.items():
            src = root / container
            if not src.is_file():
                out["errors"] += 1
                continue
            stem = Path(container).stem
            with open(src, "rb") as f:
                for a in assets:
                    if only_kinds and a.kind not in only_kinds:
                        out["skipped"] += 1
                        continue
                    ofs = a.extra.get("pck_offset")
                    if ofs is None:
                        out["skipped"] += 1
                        continue
                    try:
                        f.seek(ofs)
                        data = f.read(min(a.size, ctx.max_asset_bytes))
                        target = dest / stem / safe_rel(a.path)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(data)
                        out["extracted"] += 1
                        if len(out["samples"]) < 10:
                            out["samples"].append(a.path)
                    except OSError as exc:
                        out["errors"] += 1
                        if len(out["samples"]) < 10:
                            out["samples"].append(f"! {a.path}: {exc}")
        if out["extracted"] or out["errors"]:
            out["message"] = (f"PCK: извлечено {out['extracted']} файлов, "
                              f"ошибок {out['errors']}.")
        return out
