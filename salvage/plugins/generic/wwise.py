"""Wwise: разбор `.pck` (AKPK) и `.bnk` (BKHD/DIDX/DATA) и экспорт `.wem`.

Формат (собственное описание, сверенное на реальных банках):

AKPK (банк-пакет):
    [0x00] "AKPK"
    [0x04] uint32 header_size        (вместе с языковой/банковой/звуковой секциями)
    [0x08] uint32 flags              (0x01 — звуки адресуются языком)
    [0x0C] uint32 languages_size
    [0x10] uint32 soundbanks_size
    [0x14] uint32 streams_size
    [0x18] uint32 externals_size     (в новых версиях; в старых его нет — тогда
                                      languages+soundbanks+streams+0x10 == header_size)
    Секции идут подряд от 0x18 (или 0x14 в старой версии). Порядок таблиц:
    языки, банки (soundbanks), звуки (streams), внешние файлы.
    Запись таблицы: uint32 id, uint32 block_size, uint32 size, uint32 offset,
                    uint32 language_id
    (старая версия — size 64-битный; смещение умножается на block_size, обычно 16)

BKHD (обычный банк):
    цепочка чанков [tag:4][size:u32][payload]; нужны DIDX (индекс медиа)
    и DATA (данные). Запись DIDX — 12 байт: id, offset, size; offset считается
    от начала payload DATA.

`.wem` — это Wwise-медиа: для Vorbis версий 34–56 поток начинается с «OggS»,
но это НЕ стандартный Ogg (заголовки конкатенированы). Поэтому мы честно
отдаём `.wem` и пишем статус, а не притворяемся, что это `.ogg`.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

AKPK_MAGIC = b"AKPK"
BKHD_MAGIC = b"BKHD"


class WwiseError(ValueError):
    pass


@dataclass
class WemEntry:
    wem_id: int
    offset: int
    size: int
    language: int = 0
    source: str = ""          # "pck" | "bnk"
    container: str = ""       # файл-контейнер (posix)

    @property
    def extension(self) -> str:
        return "wem"


@dataclass
class PckFile:
    path: Path
    header_size: int
    flag: int
    version: int              # 1 — без externals, 2 — с externals
    entries: list[WemEntry] = field(default_factory=list)
    languages: dict[int, str] = field(default_factory=dict)


@dataclass
class BnkFile:
    path: Path
    version: int = 0          # dwBankGeneratorVersion из BKHD
    entries: list[WemEntry] = field(default_factory=list)
    chunks: list[tuple[str, int]] = field(default_factory=list)


def sniff(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return None
    if head == AKPK_MAGIC:
        return "pck"
    if head == BKHD_MAGIC:
        return "bnk"
    return None


# ---------------------------------------------------------------------------
# .pck (AKPK)
# ---------------------------------------------------------------------------

def read_pck(path: Path) -> PckFile:
    data = path.read_bytes()
    if data[:4] != AKPK_MAGIC:
        raise WwiseError("не AKPK")
    if len(data) < 0x18:
        raise WwiseError("обрезанный заголовок AKPK")
    header_size, flag, langs_size, banks_size, streams_size = \
        struct.unpack_from("<IIIII", data, 4)
    # порядок байт: определяем по правдоподобности header_size
    big_endian = False
    if not (0 < header_size <= len(data)):
        header_size, flag, langs_size, banks_size, streams_size = \
            struct.unpack_from(">IIIII", data, 4)
        big_endian = True
    if not (0 < header_size <= len(data)):
        raise WwiseError("AKPK: header_size вне файла")
    base = 0x10
    has_externals = langs_size + banks_size + streams_size + 0x10 != header_size
    if has_externals:
        externals_size = struct.unpack_from(">I" if big_endian else "<I", data, 0x18)[0]
        table_start = 0x1C
        version = 2
    else:
        externals_size = 0
        table_start = 0x18
        version = 1
    sections = [
        ("languages", langs_size),
        ("soundbanks", banks_size),
        ("streams", streams_size),
    ]
    if has_externals:
        sections.append(("externals", externals_size))
    p = table_start
    pck = PckFile(path=path, header_size=header_size, flag=flag, version=version)
    for name, size in sections:
        if size == 0:
            continue
        end = p + size
        if name == "languages":
            # таблица языков: uint32 name_offset, uint32 id + имена (UTF-16/UTF-8)
            q = p
            langs: list[tuple[int, int]] = []
            while q + 8 <= end:
                name_off, lang_id = struct.unpack_from(">II" if big_endian else "<II", data, q)
                q += 8
                if name_off == 0 and lang_id == 0:
                    break
                langs.append((name_off, lang_id))
            for name_off, lang_id in langs:
                str_pos = p + name_off
                pck.languages[lang_id] = _read_wide_string(data, str_pos, big_endian)
        elif name in ("soundbanks", "streams", "externals"):
            q = p
            count = struct.unpack_from(">I" if big_endian else "<I", data, q)[0] if q + 4 <= end else 0
            q += 4
            seen = 0
            max_records = max(0, (end - q) // 20)   # запись 20 байт (externals — тоже)
            limit = min(count, max_records) if count else max_records
            while seen < limit:
                if name == "externals":
                    wem_id = struct.unpack_from(">Q" if big_endian else "<Q", data, q)[0]
                    _blk, size32, offset = struct.unpack_from(
                        ">III" if big_endian else "<III", data, q + 8)
                    q += 20
                else:
                    wem_id, blk, size32, offset, lang = struct.unpack_from(
                        ">IIIII" if big_endian else "<IIIII", data, q)
                    q += 20
                    if blk and offset:
                        offset = offset * blk
                seen += 1
                if wem_id == 0 and size32 == 0:
                    continue
                if size32 == 0 or offset + size32 > len(data):
                    continue   # мусорная/недописанная запись — не изобретаем путь
                pck.entries.append(WemEntry(
                    wem_id=wem_id, offset=offset, size=size32,
                    language=0 if name == "externals" else lang,
                    source="pck", container=path.name))
        p = end
    for e in pck.entries:
        if e.offset + e.size > len(data):
            raise WwiseError(f"AKPK: запись {e.wem_id} выходит за файл")
    return pck


def _read_wide_string(data: bytes, pos: int, big_endian: bool) -> str:
    if pos + 2 > len(data):
        return ""
    # в AKPK имена языков — UTF-16 (после двух нулевых байт — конец)
    if data[pos:pos + 2] in (b"\x00\x00",):
        return ""
    # эвристика: если старший байт ASCII-пары нулевой — это UTF-16LE
    raw = data[pos:pos + 128]
    try:
        if big_endian:
            return raw.decode("utf-16-be", "ignore").split("\x00")[0]
        return raw.decode("utf-16-le", "ignore").split("\x00")[0]
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# .bnk (BKHD)
# ---------------------------------------------------------------------------

def read_bnk(path: Path) -> BnkFile:
    data = path.read_bytes()
    if data[:4] != BKHD_MAGIC:
        raise WwiseError("не BKHD")
    bank = BnkFile(path=path)
    p = 0
    chunks: dict[str, tuple[int, int]] = {}
    while p + 8 <= len(data):
        tag = data[p:p + 4].decode("latin-1")
        size = struct.unpack_from("<I", data, p + 4)[0]
        body = p + 8
        if body + size > len(data):
            raise WwiseError(f"BNK: чанк {tag} выходит за файл")
        bank.chunks.append((tag, size))
        chunks[tag] = (body, size)
        if tag == "BKHD" and size >= 8:
            # BKHD: dwBankGeneratorVersion, затем bank_id (оба uint32 LE)
            bank.version = struct.unpack_from("<I", data, body)[0]
        p = body + size
        if tag == "BKHD" and bank.version in (0,):
            break
    if "DIDX" not in chunks:
        return bank
    didx_pos, didx_size = chunks["DIDX"]
    data_pos = chunks.get("DATA", (0, 0))[0]
    count = didx_size // 12
    for i in range(count):
        wem_id, offset, size = struct.unpack_from("<III", data, didx_pos + i * 12)
        bank.entries.append(WemEntry(
            wem_id=wem_id, offset=data_pos + offset, size=size,
            source="bnk", container=path.name))
    for e in bank.entries:
        if e.offset + e.size > len(data):
            raise WwiseError(f"BNK: медиа {e.wem_id} выходит за файл")
    return bank


def read_wem_bytes(container: Path, entry: WemEntry) -> bytes:
    with open(container, "rb") as f:
        f.seek(entry.offset)
        return f.read(entry.size)


def wem_status(payload: bytes) -> str:
    """Классификация полезной нагрузки .wem — без догадок."""
    if payload[:4] == b"OggS":
        # Wwise-овский «OggS»-заголовок: стандартный Ogg-Vorbis содержит
        # идентификационный пакет с «\\x01vorbis» сразу после страницы 0.
        # У Wwise заголовки идут иначе (или их нет в потоке).
        if b"\x01vorbis" in payload[:1024]:
            return "vorbis-ogg-like"
        return "vorbis-wwise"
    if payload[:2] in (b"\xff\xfb", b"\xff\xf3", b"\xff\xf2", b"\xff\xfa"):
        return "mpeg"
    if payload[:4] == b"RIFF":
        return "riff"
    if payload[:4] == b"BKHD":
        return "bnk"
    if payload[:3] == b"RIF":  # Wwise .wem с RIFF-подобной обёрткой (XMA/ADPCM)
        return "riff"
    return "unknown"


def wem_extension(payload: bytes) -> str:
    status = wem_status(payload)
    return {"riff": "wem", "mpeg": "wem", "vorbis-ogg-like": "ogg",
            "vorbis-wwise": "wem"}.get(status, "wem")
