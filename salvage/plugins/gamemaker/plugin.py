"""GameMaker Studio-плагин (v0.2 расширенный).

Что делает:
  * data.win: карта чанков, целостность, байткод-версия;
  * спрайты: SPRT → TPAG → TXTR (страницы), кадры, rect-манифест;
  * текстуры: PNG / QOI / BZ2(+QOI/PNG) — декодирование и экспорт
    в png / qoi / bz2+qoi (см. --texture-format);
  * аудио: встроенный AUDO + внешние аудиогруппы audiogroup*.dat,
    сопоставление SOND (имя, тип, group, audio_id) → файлы;
  * имена ресурсов: OBJT/ROOM/SCPT/SHDR/FONT через STRG;
  * manifest.json: всё извлечённое + списки объектов/комнат/скриптов/шейдеров;
  * strings.txt: все строки игры.
"""
from __future__ import annotations

import json
import mmap
import struct
from pathlib import Path

from ...core import imaging
from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin
from ...core.util import classify, head_bytes, human_int, iter_files, rel_posix, safe_rel, sha256_file, sniff_magic
from .._shared import copy_verbatim, write_atomic

GM_DATA_NAMES = {"data.win", "game.win", "data.unx", "data.ios", "data.droid",
                 "game.unx", "game.ios", "game.droid", "data.android", "game.desktop",
                 "data.desktop"}
KNOWN_CHUNKS = {
    b"GEN8": "GEN8: версия байткода и общие настройки",
    b"OPTN": "OPTN: опции игры",
    b"EXPT": "EXPT: порядок загрузки",
    b"LANG": "LANG: языки/локализация",
    b"EXTN": "EXTN: расширения",
    b"SOND": "SOND: звуки",
    b"AGRP": "AGRP: аудиогруппы",
    b"SPRT": "SPRT: спрайты",
    b"BGND": "BGND: фоны",
    b"PATH": "PATH: пути движения",
    b"SCPT": "SCPT: скрипты GML",
    b"GLOB": "GLOB: глобальные переменные",
    b"SHDR": "SHDR: шейдеры",
    b"FONT": "FONT: шрифты",
    b"TMLN": "TMLN: таймлайны",
    b"OBJT": "OBJT: объекты",
    b"ROOM": "ROOM: комнаты",
    b"DAFL": "DAFL: флаги данных",
    b"TPAG": "TPAG: страницы текстур (ректы)",
    b"CODE": "CODE: байткод",
    b"VARI": "VARI: переменные",
    b"FUNC": "FUNC: функции",
    b"STRG": "STRG: строки",
    b"TXTR": "TXTR: текстуры",
    b"AUDO": "AUDO: аудиоданные",
    b"SEQN": "SEQN: последовательности",
}

# чанки со списком записей: count u32, offsets[] (абсолютные), записи
LIST_CHUNKS = {
    b"SPRT": "sprites", b"OBJT": "objects", b"ROOM": "rooms",
    b"SCPT": "scripts", b"SHDR": "shaders", b"FONT": "fonts",
    b"BGND": "backgrounds", b"SOND": "sounds", b"TMLN": "timelines",
    b"PATH": "paths", b"SEQN": "sequences",
}


class _Reader:
    """Чтение data.win: mmap при возможности, иначе обычный файл."""

    def __init__(self, path: Path):
        self.path = path
        self.size = path.stat().st_size
        self._f = open(path, "rb")
        try:
            self._m: mmap.mmap | bytes = mmap.mmap(self._f.fileno(), 0,
                                                   access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            self._m = path.read_bytes()

    def close(self) -> None:
        try:
            if isinstance(self._m, mmap.mmap):
                self._m.close()
        finally:
            self._f.close()

    def raw(self, off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > self.size:
            return b""
        return bytes(self._m[off:off + n])

    def u32(self, off: int) -> int:
        b = self.raw(off, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else 0

    def i32(self, off: int) -> int:
        b = self.raw(off, 4)
        return struct.unpack("<i", b)[0] if len(b) == 4 else 0

    def u16(self, off: int) -> int:
        b = self.raw(off, 2)
        return struct.unpack("<H", b)[0] if len(b) == 2 else 0

    def f32(self, off: int) -> float:
        b = self.raw(off, 4)
        return struct.unpack("<f", b)[0] if len(b) == 4 else 0.0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class GameMakerPlugin(EnginePlugin):
    slug = "gamemaker"
    display_name = "GameMaker Studio"
    can_extract = True
    notes = ("data.win: чанки, спрайты (SPRT/TPAG), текстуры PNG/QOI/BZ2, "
             "аудио (AUDO + audiogroup*.dat), manifest.json.")

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
        audio_groups: list[Path] = []
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
            if low.startswith("audiogroup") and low.endswith(".dat"):
                audio_groups.append(p)       # внешние аудиогруппы (FORM/DATA, но это не data.win)
            elif low in GM_DATA_NAMES or magic == "gamemaker_win":
                datas.append(p)
            elif p.suffix.lower() in (".yy", ".yyp"):
                yy_files.append(p)

        gm = ds.meta.setdefault("gamemaker", {})
        gm["audio_group_files"] = [rel_posix(p, root_r) for p in audio_groups]

        for ag in audio_groups:
            self._scan_audio_group(ds, ag, root_r)
        for p in datas:
            self._scan_data_win(ds, p, root_r, ctx)

        if ctx.deep and yy_files:
            self._scan_yy(ds, yy_files[:8000], root_r)
        if not datas and not gm.get("project_resources"):
            ds.add_finding("warn", "gm_no_data",
                           "data.win не найден — похоже на исходный проект (.yy) или неполную сборку")
        return ds

    # ------------------------------------------------------------------
    def _scan_data_win(self, ds: Dataset, path: Path, root_r: Path, ctx: EngineContext) -> None:
        rel = rel_posix(path, root_r)
        try:
            with _Reader(path) as rd:
                header = rd.raw(0, 12)
                if len(header) < 12 or header[0:4] != b"FORM" or header[8:12] != b"DATA":
                    ds.add_finding("warn", "gm_bad_header",
                                   f"{rel}: нет FORM/DATA — файл повреждён или не GameMaker",
                                   path=rel)
                    return
                declared = struct.unpack("<I", header[4:8])[0] + 8
                if declared != rd.size:
                    ds.add_finding(
                        "warn", "gm_size_mismatch",
                        f"{rel}: размер формы {human_int(declared)} Б ≠ фактических {human_int(rd.size)} Б",
                        "Файл обрезан (неполная загрузка) или дополнен данными (мод).",
                        path=rel)
                chunks = self._read_chunk_map(rd, ds, rel)
                gm = ds.meta.setdefault("gamemaker", {})
                gm["file"] = rel
                gm["chunks"] = [
                    {"tag": t.decode("latin-1"), "label": KNOWN_CHUNKS.get(t, "?"),
                     "bytes": ln, "offset": off}
                    for t, (off, ln) in chunks.items()
                ]
                gm["chunk_count"] = len(chunks)
                if b"GEN8" in chunks:
                    off8, _ = chunks[b"GEN8"]
                    gm["bytecode_hint"] = _guess_bytecode(rd.raw(off8, 8))

                manifest = self._parse_resources(rd, chunks, ds, rel, gm)
                gm["manifest"] = manifest
                self._report_gm_findings(ds, manifest, rel)
        except (OSError, struct.error) as exc:
            ds.add_finding("error", "gm_read_error", f"{rel}: {exc}", path=rel)

    # ------------------------------------------------------------------
    def _read_chunk_map(self, rd: _Reader, ds: Dataset, rel: str) -> dict[bytes, tuple[int, int]]:
        chunks: dict[bytes, tuple[int, int]] = {}
        pos = 12  # после FORM header + DATA
        while pos + 8 <= rd.size:
            tag = rd.raw(pos, 4)
            if len(tag) < 4:
                break
            length = struct.unpack("<I", rd.raw(pos + 4, 4))[0]
            if pos + 8 + length > rd.size:
                ds.add_finding("error", "gm_chunk_corrupt",
                               f"{rel}: чанк {tag!r} выходит за границы файла",
                               f"pos={pos}, length={length}, size={rd.size}", path=rel)
                break
            chunks[tag] = (pos + 8, length)
            pos += 8 + length
        return chunks

    # ------------------------------------------------------------------
    def _parse_resources(self, rd: _Reader, chunks: dict[bytes, tuple[int, int]],
                         ds: Dataset, rel: str, gm: dict) -> dict:
        manifest: dict = {"engine": "GameMaker", "source": rel, "counts": {},
                          "sprites": [], "sounds": [], "textures": [], "audio_groups": []}

        # ----- строки -----
        strings, str_base, str_off2idx = self._parse_strings(rd, chunks)

        def name_of(ptr: int) -> str | None:
            if not ptr or not strings:
                return None
            if ptr in str_off2idx:
                return strings[str_off2idx[ptr]]
            for base in (str_base, 0):
                idx = ptr - base
                if idx in str_off2idx:
                    return strings[str_off2idx[idx]]
            return None

        # ----- текстуры -----
        textures = self._parse_txtr(rd, chunks, ds, rel)
        manifest["textures"] = [
            {"index": i, "format": t["format"], "bytes": t["payload_size"]}
            for i, t in enumerate(textures)
        ]
        gm["texture_formats"] = _count_by(t["format"] for t in textures)

        # ----- TPAG -----
        tpag = self._parse_tpag(rd, chunks)
        gm["tpag_count"] = len(tpag)

        # ----- спрайты -----
        sprites = self._parse_sprt(rd, chunks, name_of, tpag, len(textures))
        manifest["sprites"] = sprites
        gm["sprite_frames"] = sum(len(s["frames"]) for s in sprites)

        # ----- аудио: SOND + AUDO -----
        sounds = self._parse_sond(rd, chunks, name_of)
        audo = self._parse_audo(rd, chunks)
        gm["audo_count"] = len(audo)
        manifest["sounds"] = sounds

        # ----- списки ресурсов с именами -----
        lists: dict[str, list[str]] = {}
        for tag, key in LIST_CHUNKS.items():
            if tag not in chunks or tag in (b"SPRT", b"SOND"):
                continue
            names = self._parse_named_list(rd, chunks, tag, name_of)
            if names:
                lists[key] = names
        manifest.update({k: v for k, v in lists.items() if k not in manifest})
        for key, names in lists.items():
            manifest["counts"][key] = len(names)
        manifest["counts"]["sprites"] = len(sprites)
        manifest["counts"]["sounds"] = len(sounds)
        manifest["counts"]["textures"] = len(textures)
        manifest["counts"]["strings"] = len(strings)

        gm["textures_full"] = textures
        gm["tpag_full"] = tpag
        gm["audo_full"] = audo
        gm["strings"] = strings[:20000]
        return manifest

    # ------------------------------------------------------------------
    def _parse_strings(self, rd: _Reader, chunks) -> tuple[list[str], int, dict[int, int]]:
        """STRG: count, offsets[], строки. В разных версиях офсеты бывают
        абсолютными или относительными к payload/заголовку — пробуем оба."""
        if b"STRG" not in chunks:
            return [], 0, {}
        off, size = chunks[b"STRG"]
        count = rd.u32(off)
        if count <= 0 or count > 5_000_000 or 4 + 4 * count > max(size, 0) + 4:
            return [], 0, {}
        offsets = [rd.u32(off + 4 + 4 * i) for i in range(count)]
        strings: list[str] = []
        off2idx: dict[int, int] = {}
        for i, so in enumerate(offsets):
            found = None
            used = None
            for cand in (so, off + so, off + 4 + 4 * count + so):
                if 0 <= cand < rd.size:
                    s = _read_cstr(rd, cand)
                    if s:
                        found, used = s, cand
                        break
            strings.append(found or "")
            if found is not None:
                off2idx.setdefault(so, i)      # по хранимому значению
                off2idx.setdefault(used, i)    # и по фактическому адресу
        return strings, 0, off2idx

    # ------------------------------------------------------------------
    def _parse_txtr(self, rd: _Reader, chunks, ds: Dataset, rel: str) -> list[dict]:
        if b"TXTR" not in chunks:
            return []
        off, size = chunks[b"TXTR"]
        count = rd.u32(off)
        if count <= 0 or count > 200_000:
            return []
        out: list[dict] = []
        for i in range(count):
            fi_off = rd.u32(off + 4 + 4 * i)
            if not (0 < fi_off < rd.size - 8):
                out.append({"index": i, "format": "bad-offset", "payload_off": 0,
                            "payload_size": 0})
                continue
            blob = rd.u32(fi_off + 4)
            info = self._sniff_texture_blob(rd, blob)
            info.update({"index": i, "fileinfo_off": fi_off, "blob_off": blob})
            out.append(info)
        return out

    def _sniff_texture_blob(self, rd: _Reader, blob: int) -> dict:
        """Блоб текстуры: u32 длина, затем PNG или BZ2(QOI) — ищем магию в окне."""
        if not (0 < blob < rd.size - 8):
            return {"format": "bad-blob", "payload_off": 0, "payload_size": 0}
        declared = rd.u32(blob)
        window = rd.raw(blob, 32)
        for delta in range(0, 17):  # магия может стоять с небольшим сдвигом
            if window[delta:delta + 8] == imaging.PNG_MAGIC:
                return {"format": "png", "payload_off": blob + delta,
                        "payload_size": max(0, declared - (delta - 4))}
            if window[delta:delta + 3] == b"BZh":
                head = rd.raw(blob + delta, min(96, max(0, declared)))
                inner, kind = imaging.bunzip_if_needed(head)
                fmt = kind if kind.startswith("bz2+") else "bz2"
                return {"format": fmt, "payload_off": blob + delta,
                        "payload_size": max(0, declared - (delta - 4))}
            if window[delta:delta + 4] == imaging.QOI_MAGIC:
                return {"format": "qoi", "payload_off": blob + delta,
                        "payload_size": max(0, declared - (delta - 4))}
        return {"format": "unknown", "payload_off": blob, "payload_size": max(0, declared)}

    # ------------------------------------------------------------------
    def _parse_tpag(self, rd: _Reader, chunks) -> list[dict]:
        if b"TPAG" not in chunks:
            return []
        off, size = chunks[b"TPAG"]
        count = rd.u32(off)
        if count <= 0 or count > 2_000_000:
            return []
        items = []
        for i in range(count):
            e = rd.u32(off + 4 + 4 * i)
            if not (0 < e < rd.size - 24):
                items.append(None)
                continue
            # раскладка записи TPAG: x,y,w,h, rx,ry, bx,by, bw,bh (10×u16), затем tex u32
            items.append({
                "x": rd.u16(e), "y": rd.u16(e + 2),
                "w": rd.u16(e + 4), "h": rd.u16(e + 6),
                "tex": rd.u32(e + 20),
            })
        return items

    # ------------------------------------------------------------------
    def _parse_sprt(self, rd: _Reader, chunks, name_of, tpag: list, tex_count: int) -> list[dict]:
        if b"SPRT" not in chunks:
            return []
        off, size = chunks[b"SPRT"]
        count = rd.u32(off)
        if count <= 0 or count > 200_000:
            return []
        sprites = []
        for i in range(count):
            e = rd.u32(off + 4 + 4 * i)
            if not (0 < e < rd.size - 40):
                continue
            name = name_of(rd.u32(e)) or f"sprite_{i}"
            w, h = rd.i32(e + 4), rd.i32(e + 8)
            # GMS2-подобная раскладка: name(4) w,h(8) margins(16) unknown[3](12)
            # bbox+sepmask(8) ox,oy(8) => texcount на смещении 56
            tcount_off = e + 56
            tcount = rd.i32(tcount_off)
            frames: list[int] = []
            if 0 < tcount <= 4096 and tcount_off + 4 + 4 * tcount < rd.size:
                frames = [rd.i32(tcount_off + 4 + 4 * k) for k in range(tcount)]
            valid = [f for f in frames if 0 <= f < len(tpag)]
            sprites.append({
                "index": i, "name": name, "width": w if 0 < w < 65536 else 0,
                "height": h if 0 < h < 65536 else 0,
                "frames": [{"tpag": f} for f in valid],
                "raw_frame_count": len(frames),
            })
        return sprites

    # ------------------------------------------------------------------
    def _parse_sond(self, rd: _Reader, chunks, name_of) -> list[dict]:
        if b"SOND" not in chunks:
            return []
        off, size = chunks[b"SOND"]
        count = rd.u32(off)
        if count <= 0 or count > 100_000:
            return []
        out = []
        for i in range(count):
            e = rd.u32(off + 4 + 4 * i)
            if not (0 < e < rd.size - 32):
                continue
            name = name_of(rd.u32(e)) or f"sound_{i}"
            snd_type = name_of(rd.u32(e + 8)) or "?"
            group = max(0, rd.i32(e + 28))
            audio_id = rd.i32(e + 32)
            out.append({"index": i, "name": name, "type": snd_type,
                        "group": group, "audio_id": audio_id})
        return out

    # ------------------------------------------------------------------
    def _parse_audo(self, rd: _Reader, chunks) -> list[dict]:
        if b"AUDO" not in chunks:
            return []
        off, size = chunks[b"AUDO"]
        count = rd.u32(off)
        if count <= 0 or count > 100_000:
            return []
        out = []
        for i in range(count):
            e = rd.u32(off + 4 + 4 * i)
            if not (0 < e < rd.size - 4):
                out.append({"index": i, "offset": 0, "length": 0})
                continue
            length = rd.u32(e)
            out.append({"index": i, "offset": e + 4, "length": length})
        return out

    # ------------------------------------------------------------------
    def _parse_named_list(self, rd: _Reader, chunks, tag: bytes, name_of) -> list[str]:
        off, size = chunks[tag]
        count = rd.u32(off)
        if count <= 0 or count > 500_000 or 4 + 4 * count > max(size, 0) + 4:
            return []
        names = []
        for i in range(count):
            e = rd.u32(off + 4 + 4 * i)
            if not (0 < e < rd.size - 4):
                continue
            n = name_of(rd.u32(e))
            if n:
                names.append(n)
        return names

    # ------------------------------------------------------------------
    def _scan_audio_group(self, ds: Dataset, path: Path, root_r: Path) -> None:
        rel = rel_posix(path, root_r)
        try:
            with _Reader(path) as rd:
                if rd.raw(0, 12)[8:12] != b"DATA":
                    ds.add_finding("warn", "gm_group_bad", f"{rel}: не FORM/DATA", path=rel)
                    return
                chunks = self._read_chunk_map(rd, ds, rel)
                audo = self._parse_audo(rd, chunks)
                gm = ds.meta.setdefault("gamemaker", {})
                gm.setdefault("audio_groups", []).append(
                    {"file": rel, "audio_count": len(audo),
                     "group": _group_number(path.name) or (len(gm.get("audio_groups", [])) + 1),
                     "chunks": [t.decode("latin-1") for t in chunks]})
                ds.add_finding("info", "gm_audiogroup",
                               f"{rel}: внешняя аудиогруппа, звуков {len(audo)}", path=rel)
        except OSError as exc:
            ds.add_finding("error", "gm_group_error", f"{rel}: {exc}", path=rel)

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
            gm = ds.meta.setdefault("gamemaker", {})
            gm["project_resources"] = dict(sorted(counts.items(), key=lambda kv: -kv[1]))
            ds.add_finding(
                "info", "gm_project",
                f"Исходный проект GameMaker: {sum(counts.values())} ресурсов",
                ", ".join(f"{k}×{v}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:10]))

    # ------------------------------------------------------------------
    def _report_gm_findings(self, ds: Dataset, manifest: dict, rel: str) -> None:
        counts = manifest.get("counts", {})
        if counts:
            ds.add_finding(
                "info", "gm_chunk_map",
                f"{rel}: спрайтов {counts.get('sprites', 0)}, звуков {counts.get('sounds', 0)}, "
                f"текстур {counts.get('textures', 0)}, строк {counts.get('strings', 0)}",
                "Ресурсы: " + ", ".join(f"{k}×{v}" for k, v in
                                       sorted(counts.items(), key=lambda kv: -kv[1])[:10]),
                path=rel)
        fmts = ds.meta.get("gamemaker", {}).get("texture_formats", {})
        if fmts:
            ds.add_finding("info", "gm_texture_formats",
                           "Форматы текстурных страниц: " +
                           ", ".join(f"{k}×{v}" for k, v in sorted(fmts.items())),
                           "BZ2+QOI поддерживается (декодер встроен), PNG — напрямую.", path=rel)
        # звуки, ссылающиеся на внешние группы, которых нет
        groups = {g["file"].rsplit("/", 1)[-1] for g in
                  ds.meta.get("gamemaker", {}).get("audio_groups", [])}
        missing: dict[int, int] = {}
        embedded = external = 0
        for s in manifest.get("sounds", []):
            if s["group"] == 0:
                embedded += 1
                continue
            external += 1
            fname = f"audiogroup{s['group']}.dat"
            if fname not in groups:
                missing[s["group"]] = missing.get(s["group"], 0) + 1
        ds.meta["gamemaker"]["sounds_embedded"] = embedded
        ds.meta["gamemaker"]["sounds_external"] = external
        if missing:
            ds.add_finding(
                "warn", "gm_missing_audiogroups",
                f"Звуки ссылаются на отсутствующие аудиогруппы: {len(missing)}",
                "; ".join(f"audiogroup{g}.dat ({n} звуков)" for g, n in sorted(missing.items())),
                count=sum(missing.values()))

    # ------------------------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        overwritten = 0
        base = copy_verbatim(dataset, dest, ctx, only_kinds)
        gm = dataset.meta.get("gamemaker") or {}
        manifest = gm.get("manifest")
        if not manifest:
            return base
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        texture_format = (ctx.keys.get("texture_format") or "png").lower()
        dest = Path(dest)
        manifest_out = dict(manifest)
        manifest_out["extraction"] = {"texture_format": texture_format, "files": []}

        def add_file(rel_path: str, data: bytes) -> None:
            overwritten = 0
            target = dest / safe_rel(rel_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            overwritten += write_atomic(target, data)
            out["extracted"] += 1
            manifest_out["extraction"]["files"].append(rel_path)
            if len(out["samples"]) < 12:
                out["samples"].append(rel_path)

        # --- текстуры ---
        want_tex = only_kinds is None or "texture" in only_kinds
        pages: dict[int, dict] = {}
        if want_tex:
            pages = self._extract_textures(dataset, dest, gm, texture_format, add_file, out)
        # --- спрайты (кадры) ---
        if want_tex and gm.get("manifest"):
            self._extract_sprite_frames(dataset, dest, manifest, pages, add_file, out)
        # --- аудио ---
        want_audio = only_kinds is None or "audio" in only_kinds
        if want_audio:
            self._extract_audio(dataset, dest, gm, add_file, out)
        # --- строки и манифест ---
        if gm.get("strings"):
            add_file("strings.txt", "\n".join(gm["strings"]).encode("utf-8"))
        add_file("manifest.json",
                 json.dumps(manifest_out, ensure_ascii=False, indent=1).encode("utf-8"))
        out["message"] = (f"GameMaker: файлов {out['extracted']} "
                          f"(текстуры: {texture_format}), ошибок {out['errors']}.")
        base["extracted"] += out["extracted"]
        base["errors"] += out["errors"]
        base["samples"] = (base["samples"] + out["samples"])[:20]
        base["message"] = (base["message"] + " " + out["message"]).strip()
        return base

    # ------------------------------------------------------------------
    def _extract_textures(self, dataset: Dataset, dest: Path, gm: dict,
                          texture_format: str, add_file, out: dict) -> dict[int, dict]:
        """Экспорт страниц в выбранном формате. Возвращает {index: {png, w, h}}."""
        pages: dict[int, dict] = {}
        src = dataset.root / (gm.get("file") or "")
        textures = gm.get("textures_full") or []
        if not textures or not src.is_file():
            return pages
        try:
            with _Reader(src) as rd:
                for t in textures:
                    idx = t.get("index", 0)
                    payload = rd.raw(t.get("payload_off", 0), t.get("payload_size", 0))
                    if not payload:
                        out["errors"] += 1
                        continue
                    inner, kind = imaging.bunzip_if_needed(payload)
                    png: bytes | None = None
                    w = h = 0
                    if kind in ("png", "bz2+png") and inner[:8] == imaging.PNG_MAGIC:
                        png = inner
                        dims = _png_dims(inner)
                        if dims:
                            w, h = dims
                    elif kind in ("qoi", "bz2+qoi"):
                        try:
                            w, h, rgba = imaging.decode_qoi(inner)
                            png = imaging.encode_png_rgba(rgba, w, h)
                        except ValueError as exc:
                            out["errors"] += 1
                            if len(out["samples"]) < 12:
                                out["samples"].append(f"! texture {idx}: {exc}")
                            continue
                    else:
                        out["skipped"] += 1
                        continue
                    if png is None:
                        out["skipped"] += 1
                        continue
                    pages[idx] = {"png": png, "w": w, "h": h}
                    name = f"textures/tex_{idx:03d}"
                    if texture_format == "png":
                        add_file(name + ".png", png)
                    elif texture_format == "qoi":
                        rgba = imaging.to_rgba(png)
                        add_file(name + ".qoi",
                                 imaging.encode_qoi(rgba[2], rgba[0], rgba[1])
                                 if rgba else png)
                    elif texture_format in ("bz2", "bz2+qoi", "bz2qoi"):
                        rgba = imaging.to_rgba(png)
                        qoi = (imaging.encode_qoi(rgba[2], rgba[0], rgba[1])
                               if rgba else png)
                        add_file(name + ".qoi.bz2", imaging.bz2.compress(qoi))
                    else:  # both: png + оригинальный формат
                        add_file(name + ".png", png)
        except OSError as exc:
            out["errors"] += 1
            out["samples"].append(f"! textures: {exc}")
        gm["pages_exported"] = len(pages)
        return pages

    def _extract_sprite_frames(self, dataset: Dataset, dest: Path, manifest: dict,
                               pages: dict[int, dict], add_file, out: dict) -> None:
        extras = (dataset.meta.get("gamemaker") or {}).get("tpag_full") or []
        use_pillow = imaging.pillow() is not None
        for sp in manifest.get("sprites", []):
            frames = sp.get("frames") or []
            if not frames:
                continue
            for fi, f in enumerate(frames):
                ti = f.get("tpag")
                if ti is None or ti >= len(extras) or extras[ti] is None:
                    continue
                rect = extras[ti]
                page = pages.get(rect["tex"])
                if not page:
                    continue
                name = f"sprites/{safe_rel(sp['name']) or 'sprite'}_{fi:02d}"
                if use_pillow:
                    crop = imaging.crop_png(page["png"], rect["x"], rect["y"],
                                            rect["w"], rect["h"])
                    if crop:
                        add_file(name + ".png", crop)
                        f["extracted"] = name + ".png"
                        continue
                # без Pillow: отдаём целую страницу + точный rect в манифесте
                f["page"] = rect["tex"]
                f["rect"] = [rect["x"], rect["y"], rect["w"], rect["h"]]
        if not use_pillow and manifest.get("sprites"):
            out["message"] = (out.get("message", "") +
                              " Кадры спрайтов: установите Pillow для нарезки "
                              "(pip install pillow); сейчас в манифесте rect-координаты.")

    def _extract_audio(self, dataset: Dataset, dest: Path, gm: dict,
                       add_file, out: dict) -> None:
        names_by_group: dict[int, dict[int, str]] = {}
        for s in (gm.get("manifest") or {}).get("sounds", []):
            names_by_group.setdefault(s["group"], {})[s["audio_id"]] = s["name"]

        # --- встроенный AUDO из data.win ---
        gm_file = gm.get("file")
        if gm_file:
            src = dataset.root / gm_file
            try:
                with _Reader(src) as rd:
                    for entry in gm.get("audo_full") or []:
                        length = entry.get("length", 0)
                        if length <= 0:
                            continue
                        blob = rd.raw(entry["offset"], min(length, 64 << 20))
                        if not blob:
                            continue
                        name = names_by_group.get(0, {}).get(entry["index"],
                                                            f"audio_{entry['index']:03d}")
                        add_file(f"audio/{safe_rel(name)}.{_audio_ext(blob)}", blob)
            except OSError as exc:
                out["errors"] += 1
                out["samples"].append(f"! audo: {exc}")

        # --- внешние аудиогруппы ---
        for g in gm.get("audio_groups", []):
            gpath = dataset.root / g["file"]
            try:
                with _Reader(gpath) as rd:
                    chunks = self._read_chunk_map(rd, dataset, g["file"])
                    for entry in self._parse_audo(rd, chunks):
                        length = entry.get("length", 0)
                        if length <= 0:
                            continue
                        blob = rd.raw(entry["offset"], min(length, 64 << 20))
                        if not blob:
                            continue
                        name = names_by_group.get(g.get("group", 0), {}).get(
                            entry["index"], f"audio_{entry['index']:03d}")
                        add_file(f"audio/{safe_rel(name)}.{_audio_ext(blob)}", blob)
            except OSError as exc:
                out["errors"] += 1
                out["samples"].append(f"! {g['file']}: {exc}")


def _group_number(filename: str) -> int:
    import re
    m = re.search(r"audiogroup(\d+)", filename, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def _audio_ext(blob: bytes) -> str:
    if blob.startswith(b"OggS"):
        return "ogg"
    if blob.startswith(b"RIFF"):
        return "wav"
    if blob.startswith(b"\xff\xf3") or blob.startswith(b"ID3"):
        return "mp3"
    return "bin"


def _png_dims(png: bytes) -> tuple[int, int] | None:
    if len(png) < 24 or png[:8] != imaging.PNG_MAGIC:
        return None
    w, h = struct.unpack(">II", png[16:24])
    return w, h


def _count_by(it) -> dict[str, int]:
    out: dict[str, int] = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return out


def _read_cstr(rd: _Reader, off: int, limit: int = 512) -> str | None:
    if off <= 0 or off >= rd.size:
        return None
    raw = rd.raw(off, min(limit, rd.size - off))
    if not raw:
        return None
    z = raw.find(b"\x00")
    if z < 0:
        return None
    try:
        s = raw[:z].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in s):
        return None
    if len(raw[:z]) == 0 and off != 0:
        return ""  # пустая строка допустима
    return s


def _guess_bytecode(payload: bytes) -> str:
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
