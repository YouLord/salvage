"""GameMaker Studio-плагин: карта чанков data.win, проект .yy/.yyp, целостность."""
from __future__ import annotations

import json
import struct
from pathlib import Path

from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin
from ...core.util import classify, head_bytes, human_int, iter_files, rel_posix, safe_rel, sha256_file, sniff_magic
from .._shared import copy_verbatim

GM_DATA_NAMES = {"data.win", "game.win", "data.unx", "data.ios", "data.droid",
                 "game.unx", "game.ios", "game.droid", "data.android"}
KNOWN_CHUNKS = {
    b"GEN8": "GEN8 (общие настройки, версия байткода)",
    b"OPTN": "OPTN (настройки игры)",
    b"EXPT": "EXPT (порядок загрузки)",
    b"LANG": "LANG (языки/локализация)",
    b"EXTN": "EXTN (расширения)",
    b"SOND": "SOND (звуки)",
    b"AGRP": "AGRP (аудиогруппы)",
    b"SPRT": "SPRT (спрайты)",
    b"BGND": "BGND (фоны)",
    b"PATH": "PATH (пути)",
    b"SCPT": "SCPT (скрипты GML)",
    b"GLOB": "GLOB (глобальные переменные)",
    b"SHDR": "SHDR (шейдеры)",
    b"FONT": "FONT (шрифты)",
    b"TMLN": "TMLN (таймлайны)",
    b"OBJT": "OBJT (объекты)",
    b"ROOM": "ROOM (комнаты)",
    b"DAFL": "DAFL (флаги данных)",
    b"TPAG": "TPAG (страницы текстур)",
    b"CODE": "CODE (байткод)",
    b"VARI": "VARI (переменные)",
    b"FUNC": "FUNC (функции)",
    b"STRG": "STRG (строки)",
    b"TXTR": "TXTR (текстуры)",
    b"AUDO": "AUDO (аудио)",
}


class GameMakerPlugin(EnginePlugin):
    slug = "gamemaker"
    display_name = "GameMaker Studio"
    can_extract = True
    notes = "data.win: карта чанков и целостность; .yy/.yyp: инвентарь ресурсов."

    # ------------------------------------------------------------------
    def detect(self, root: Path) -> tuple[float, list[str]]:
        score = 0.0
        evidence: list[str] = []
        yy = yyp = data = 0
        for p in iter_files(root):
            low = p.name.lower()
            if low in GM_DATA_NAMES:
                data += 1
                evidence.append(f"{p.name}: {rel_posix(p, root) if p.parent != root else p.name}")
            elif p.suffix.lower() in (".yy", ".yyp"):
                yy += 1
            head = head_bytes(p, 12)
            if head.startswith(b"FORM") and head[8:12] == b"DATA":
                if low not in GM_DATA_NAMES:
                    data += 1
                    evidence.append(f"FORM/DATA: {p.name}")
            if score >= 0.95:
                break
        if data:
            score += min(0.8, 0.4 * data)
        if yy:
            score += min(0.5, 0.02 * yy)
            evidence.append(f"{yy} файлов .yy/.yyp")
        if yyp:
            score += 0.1
        return min(score, 0.98), evidence[:8]

    # ------------------------------------------------------------------
    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        root_r = root.resolve()
        datas: list[Path] = []
        yy_files: list[Path] = []
        for p in iter_files(root, exclude=ctx.exclude):
            rel = rel_posix(p, root_r)
            try:
                size = p.stat().st_size
            except OSError:
                continue
            head = head_bytes(p, 12)
            magic = sniff_magic(head, rel)
            kind = classify(rel, magic)
            sha = sha256_file(p) if (ctx.hash_files and size <= ctx.hash_limit_mb << 20) else None
            a = ds.add_asset(rel, kind=kind, size=size, sha256=sha)
            if magic:
                a.extra["magic"] = magic
            low = p.name.lower()
            if low in GM_DATA_NAMES or magic == "gamemaker_win":
                datas.append(p)
            elif p.suffix.lower() in (".yy", ".yyp"):
                yy_files.append(p)

        for p in datas:
            self._scan_data_win(ds, p, root_r, ctx)
        if ctx.deep and yy_files:
            self._scan_yy(ds, yy_files[:8000], root_r)
        if not datas and not ds.meta.get("gamemaker_project"):
            ds.add_finding("warn", "gm_no_data",
                           "data.win не найден — похоже на исходный проект (.yy) или неполную сборку")
        return ds

    # ------------------------------------------------------------------
    def _scan_data_win(self, ds: Dataset, path: Path, root_r: Path, ctx: EngineContext) -> None:
        rel = rel_posix(path, root_r)
        try:
            size = path.stat().st_size
        except OSError:
            return
        try:
            with open(path, "rb") as f:
                header = f.read(12)
                if len(header) < 12 or header[0:4] != b"FORM" or header[8:12] != b"DATA":
                    ds.add_finding("warn", "gm_bad_header",
                                   f"{rel}: нет FORM/DATA — файл повреждён или не GameMaker",
                                   path=rel)
                    return
                form_size = struct.unpack("<I", header[4:8])[0]
                declared = form_size + 8
                if declared != size:
                    ds.add_finding(
                        "warn", "gm_size_mismatch",
                        f"{rel}: размер формы {human_int(declared)} Б ≠ фактических {human_int(size)} Б",
                        "Файл обрезан (неполная загрузка) или дополнен данными (мод).",
                        path=rel)
                chunks = []
                while True:
                    pos = f.tell()
                    if pos + 8 > size:
                        break
                    tag = f.read(4)
                    if len(tag) < 4:
                        break
                    length = struct.unpack("<I", f.read(4))[0]
                    if length < 0 or pos + 8 + length > size:
                        ds.add_finding(
                            "error", "gm_chunk_corrupt",
                            f"{rel}: чанк {tag!r} выходит за границы файла",
                            f"pos={pos}, length={length}, size={size}", path=rel)
                        break
                    chunks.append((tag, length, pos))
                    f.seek(length, 1)
                    if tag == b"GEN8" and chunks and len(chunks) == 1:
                        f.seek(pos + 8)
                        payload = f.read(min(length, 64))
                        ds.meta.setdefault("gamemaker", {})["bytecode_hint"] = _guess_bytecode(payload)
                    else:
                        pass
                tags = [c[0].decode("latin-1") for c in chunks]
                ds.meta.setdefault("gamemaker", {})["file"] = rel
                ds.meta["gamemaker"]["chunks"] = [
                    {"tag": c[0].decode("latin-1"),
                     "label": KNOWN_CHUNKS.get(c[0], "?"),
                     "bytes": c[1], "offset": c[2]}
                    for c in chunks
                ]
                ds.meta["gamemaker"]["chunk_count"] = len(chunks)
                unknown = [t for t in tags if t.encode() not in KNOWN_CHUNKS]
                ds.add_finding(
                    "info", "gm_chunk_map",
                    f"{rel}: {len(chunks)} чанков, байткод {ds.meta['gamemaker'].get('bytecode_hint', '?')}",
                    "Чанки: " + ", ".join(f"{t}({human_int(l)})" for t, l, _ in chunks[:14]),
                    path=rel)
                if unknown:
                    ds.add_finding("info", "gm_unknown_chunks",
                                   f"Неизвестные чанки: {', '.join(unknown)}",
                                   "Вероятно, новая версия формата — см. roadmap.", path=rel)
        except (OSError, struct.error) as exc:
            ds.add_finding("error", "gm_read_error", f"{rel}: {exc}", path=rel)

    # ------------------------------------------------------------------
    def _scan_yy(self, ds: Dataset, files: list[Path], root_r: Path) -> None:
        counts: dict[str, int] = {}
        for p in files:
            try:
                data = json.loads(p.read_text("utf-8", errors="ignore"))
            except (OSError, ValueError):
                continue
            model = data.get("modelName") or data.get("resourceType")
            if not model:
                continue
            counts[model] = counts.get(model, 0) + 1
        if counts:
            ds.meta.setdefault("gamemaker", {})["project_resources"] = dict(
                sorted(counts.items(), key=lambda kv: -kv[1]))
            ds.add_finding(
                "info", "gm_project",
                f"Исходный проект GameMaker: {sum(counts.values())} ресурсов",
                ", ".join(f"{k}×{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:10]))

    # ------------------------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        summary = copy_verbatim(dataset, dest, ctx, only_kinds)
        summary["message"] += (" Байткод GML не декомпилируется (см. roadmap: CODE/STRG-парсер). "
                               "data.win сохранён побайтово.")
        return summary


def _guess_bytecode(payload: bytes) -> str:
    """Эвристика: GEN8 → байт флага, затем varint версии байткода."""
    if not payload:
        return "?"
    i = 1
    val = shift = 0
    while i < len(payload) and i < 8:
        b = payload[i]
        val |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        i += 1
    if 10 <= val <= 22:
        return f"v{val} (оценка)"
    return "?"
