"""Общие утилиты: классификация файлов, магия форматов, хэши, энтропия."""
from __future__ import annotations

import hashlib
import math
import os
import re
from pathlib import Path
from typing import Iterable, Iterator

# ---------------------------------------------------------------------------
# Классификация по расширению
# ---------------------------------------------------------------------------

_EXT_KIND: dict[str, str] = {}


def _fill(kind: str, exts: str) -> None:
    for e in exts.split():
        _EXT_KIND[e] = kind


_fill("texture", "png jpg jpeg webp tga bmp dds ktx ktx2 astc pvr svg exr hdr gif psd "
                 "ctex stex tex avif")
_fill("audio", "wav ogg mp3 m4a aac flac opus wma xm mod s3m it oggvorbis")
_fill("video", "mp4 webm ogv bik usm avi mov bk2 mkv")
_fill("mesh", "obj fbx gltf glb dae blend stl ply smd")
_fill("font", "ttf otf woff woff2 fnt pfb pfm")
_fill("shader", "shader cginc hlsl glsl vert frag comp geom metal gdshader gdshaderinc")
_fill("scene", "unity tscn scn escn umap map rmap rmmzmap rxdata rvdata rvdata2 level "
               "unr tilemap tmx")
_fill("anim", "anim controller overridecontroller clip animation mtn track mesh")
_fill("script", "cs js jslib lua luac py pyc rb rbc gd gdc gml yy por nut as hx java "
                "jsc dex kt kts ts sh bat cmd")
_fill("binary", "dll so dylib exe wasm a aab")
_fill("data", "json xml yaml yml csv ini toml dat bytes asset cfg txt bin manifest "
              "res resx tpsheet meta import remap csproj sln props atlases stat "
              "gmljson yy yyp plist strings po mo")
_fill("archive", "pck zip pak dpk apk xapk ipa obb love vpk wad arc gmx bundle "
                 "assets unity3d resource rpa rpak rgssad rgss3a dwf utoc ucas "
                 "nsp xci tar gz bz2 xz 7z rar zst")
_fill("script", "gdc luac jsc rpyc")


_MAGIC: list[tuple[bytes, str]] = [
    (b"UnityFS\x00", "unityfs"),
    (b"UnityWeb", "unityweb"),
    (b"UnityRaw", "unityraw"),
    (b"UnityArchive", "unityarchive"),
    (b"GDPC", "godot_pck"),
    (b"ECFG", "godot_ecfg"),
    (b"RPA-3", "renpy_rpa3"),
    (b"RPA-2", "renpy_rpa2"),
    (b"RGSSAD\x00\x01", "rgssad1"),
    (b"RGSSAD\x00\x03", "rgssad3"),
    (b"RENPY RPC2", "renpy_rpc2"),
    (b"SQLite format 3", "sqlite"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip_empty"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF8", "gif"),
    (b"RIFF", "riff"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3"),
    (b"\x7fELF", "elf"),
    (b"MZ", "pe"),
    (b"dex\n", "dex"),
    (b"<?xml", "xml"),
    (b"{", "json_maybe"),
    (b"[", "json_maybe"),
]


def head_bytes(path: Path, n: int = 64) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def sniff_magic(head: bytes, name: str = "") -> str | None:
    """Определить формат по первым байтам. Возвращает короткий код или None."""
    for sig, code in _MAGIC:
        if head.startswith(sig):
            # особые случаи
            if code == "riff":
                kind = head[8:12]
                if kind == b"WEBP":
                    return "webp"
                if kind == b"WAVE":
                    return "wav"
                return "riff"
            if code == "json_maybe":
                # ложно-положительные на тексте — уточняем по расширению
                return "json" if name.lower().endswith(".json") else None
            return code
    # GameMaker: FORM....DATA
    if head.startswith(b"FORM") and len(head) >= 12 and head[8:12] == b"DATA":
        return "gamemaker_win"
    return None


def ext_of(name: str) -> str:
    name = name.lower()
    if "." not in name.rsplit("/", 1)[-1]:
        return ""
    return name.rsplit(".", 1)[-1]


def classify(name: str, extra_magic: str | None = None) -> str:
    """kind по имени файла (+ подсказка от магии формата)."""
    base = name.rsplit("/", 1)[-1].lower()
    if base in ("data.win", "game.win", "data.unx", "data.ios", "data.android", "game.unx"):
        return "archive"
    ext = ext_of(name) if not base.startswith(".") else ""
    # у составных расширений вида .png.import / .ogg.import берём первый сегмент
    if ext in ("import", "remap", "meta"):
        parts = base.split(".")
        if len(parts) >= 3:
            ext0 = parts[-2]
            if ext0 in _EXT_KIND:
                return _EXT_KIND[ext0]
    kind = _EXT_KIND.get(ext)
    if kind:
        return kind
    if extra_magic in ("png", "jpg", "webp", "gif", "dds"):
        return "texture"
    if extra_magic in ("ogg", "wav", "mp3", "riff"):
        return "audio"
    if extra_magic in ("zip", "gzip", "zstd", "xz", "bzip2", "godot_pck",
                       "renpy_rpa3", "renpy_rpa2", "rgssad1", "rgssad3",
                       "gamemaker_win", "unityfs", "unityweb", "unityraw"):
        return "archive"
    if extra_magic in ("json", "xml"):
        return "data"
    if extra_magic in ("elf", "pe"):
        return "binary"
    return "other"


KIND_LABELS_RU = {
    "texture": "Текстуры", "audio": "Аудио", "video": "Видео", "mesh": "Модели",
    "font": "Шрифты", "shader": "Шейдеры", "scene": "Сцены / уровни",
    "anim": "Анимации", "script": "Скрипты / код", "data": "Данные",
    "archive": "Архивы", "binary": "Бинарники", "other": "Прочее",
}

# ---------------------------------------------------------------------------
# Файловая система
# ---------------------------------------------------------------------------

SKIP_DIR_NAMES = {".git", ".svn", ".hg", "__pycache__", "node_modules", ".idea", ".vs"}


def iter_files(
    root: Path, exclude: Iterable[Path] = (), max_files: int = 2_000_000,
) -> Iterator[Path]:
    """Обход файлов с защитой от циклов, системного мусора и нашего out-каталога."""
    root = root.resolve()
    excl = [p.resolve() for p in exclude]
    count = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        dirnames[:] = sorted(
            n for n in dirnames
            if n not in SKIP_DIR_NAMES
            and (d / n).resolve() not in excl
        )
        for name in sorted(filenames):
            p = d / name
            try:
                if p.is_symlink():
                    continue
            except OSError:
                continue
            yield p
            count += 1
            if count >= max_files:
                return


def rel_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


_BAD_CHARS = re.compile(r'[\x00-\x1f\x7f:*?"<>|]')


def safe_rel(rel: str) -> str:
    """Безопасный относительный путь (защита от ../ и недопустимых символов)."""
    rel = rel.replace("\\", "/")
    parts: list[str] = []
    for seg in rel.split("/"):
        seg = seg.strip()
        if seg in ("", ".", ".."):
            continue
        seg = _BAD_CHARS.sub("_", seg)
        if len(seg) > 120:
            stem, dot, ext = seg.rpartition(".")
            if dot and len(ext) <= 10:
                seg = stem[: 120 - len(ext) - 1] + "." + ext
            else:
                seg = seg[:120]
        parts.append(seg)
    out = "/".join(parts)
    return out[:1024]


def sha256_file(path: Path, block: int = 1 << 20) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(block)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def entropy(data: bytes) -> float:
    """Шенноновская энтропия (бит/байт) для оценки сжатия/шифрования."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def entropy_of_file(path: Path, limit: int = 65536) -> float:
    try:
        with open(path, "rb") as f:
            return entropy(f.read(limit))
    except OSError:
        return 0.0

# ---------------------------------------------------------------------------
# Форматирование
# ---------------------------------------------------------------------------


def human_bytes(n: float | int) -> str:
    if n is None:
        return "—"
    n = float(n)
    for unit in ("Б", "КБ", "МБ", "ГБ", "ТБ"):
        if abs(n) < 1024 or unit == "ТБ":
            if unit == "Б":
                return f"{int(n)} Б"
            return f"{n:.1f} {unit}".replace(".0 ", " ")
        n /= 1024
    return f"{n:.1f} ТБ"


def human_int(n: int) -> str:
    return f"{n:,}".replace(",", " ")


def mask_secret(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 8:
        return s[:2] + "…"
    return s[:6] + "…" + s[-2:]
