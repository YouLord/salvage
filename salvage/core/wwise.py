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
    bank_id: int = 0
    language: int = 0
    entries: list[WemEntry] = field(default_factory=list)
    chunks: list[tuple[str, int]] = field(default_factory=list)
    # HIRC: только инвентарь (тип объекта → сколько), без графа событий
    hirc_total: int = 0
    hirc_types: dict[int, int] = field(default_factory=dict)
    hirc_error: str = ""      # если HIRC не разобрался — честная причина


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

HIRC_TYPE_NAMES = {
    1: "settings", 2: "sound", 3: "action", 4: "event", 5: "random/sequence",
    6: "switch", 7: "actor-mixer", 8: "bus", 9: "layer", 10: "music-segment",
    11: "music-track", 12: "music-switch", 13: "music-playlist",
    14: "music-state", 15: "state", 16: "feedback", 17: "dialogue-event",
    18: "motion-bus", 19: "motion-fx", 20: "effect", 21: "aux-bus",
}


def read_bnk(path: Path) -> BnkFile:
    """Прочитать .bnk последовательно по чанкам: [tag:4][size:u32][payload].

    Никаких предположений о фиксированных смещениях: каждый чанк читается
    по своей длине, выход за файл — WwiseError, а не «набор правдоподобных
    записей». DATA служит базой для offset'ов из DIDX.
    """
    data = path.read_bytes()
    if data[:4] != BKHD_MAGIC:
        raise WwiseError("не BKHD")
    bank = BnkFile(path=path)
    # позиции payload'ов чанков (первое вхождение тега — как в реальных банках)
    chunks: dict[str, tuple[int, int]] = {}
    p = 0
    while p + 8 <= len(data):
        tag = data[p:p + 4].decode("latin-1")
        size = struct.unpack_from("<I", data, p + 4)[0]
        body = p + 8
        if body + size > len(data):
            raise WwiseError(
                f"BNK: чанк {tag} (смещение {p}, длина {size}) выходит за файл "
                f"({len(data)} Б)")
        bank.chunks.append((tag, size))
        chunks.setdefault(tag, (body, size))
        if tag == "BKHD" and size >= 8:
            # BKHD: dwBankGeneratorVersion (u32), затем bank_id (u32);
            # язык/прочее — только если поле реально есть
            bank.version, bank.bank_id = struct.unpack_from("<II", data, body)
            if size >= 12:
                bank.language = struct.unpack_from("<I", data, body + 8)[0]
        p = body + size
    if "BKHD" not in chunks:
        raise WwiseError("BNK без чанка BKHD")

    # --- DIDX + DATA ---
    if "DIDX" in chunks:
        didx_pos, didx_size = chunks["DIDX"]
        if didx_size % 12:
            raise WwiseError(f"DIDX: размер {didx_size} не кратен 12")
        if "DATA" not in chunks:
            raise WwiseError("DIDX есть, а DATA нет — смещения некуда отсчитывать")
        data_pos, data_size = chunks["DATA"]
        for i in range(didx_size // 12):
            wem_id, offset, size = struct.unpack_from("<III", data, didx_pos + i * 12)
            if size == 0:
                continue
            abs_offset = data_pos + offset
            if abs_offset + size > len(data):
                raise WwiseError(
                    f"BNK: медиа {wem_id} (offset {offset}, size {size}) "
                    f"выходит за DATA/файл")
            bank.entries.append(WemEntry(wem_id=wem_id, offset=abs_offset,
                                         size=size, source="bnk",
                                         container=path.name))

    # --- HIRC: минимальный инвентарь ---
    if "HIRC" in chunks:
        hirc_pos, hirc_size = chunks["HIRC"]
        _read_hirc_inventory(data[hirc_pos:hirc_pos + hirc_size], bank)
    return bank


def _read_hirc_inventory(buf: bytes, bank: BnkFile) -> None:
    """Посчитать объекты HIRC по типам (без разбора свойств и связей).

    Структура: uint32 count, затем count × (uint8 type, uint32 size, payload).
    Если длины не сходятся — фиксируем hirc_error, а не молчим.
    """
    if len(buf) < 4:
        bank.hirc_error = "HIRC короче 4 байт"
        return
    count = struct.unpack_from("<I", buf, 0)[0]
    p = 4
    seen = 0
    for _ in range(count):
        if p + 5 > len(buf):
            bank.hirc_error = f"HIRC обрезан: {seen} из {count} объектов"
            break
        obj_type = buf[p]
        size = struct.unpack_from("<I", buf, p + 1)[0]
        p += 5
        if p + size > len(buf):
            bank.hirc_error = f"HIRC: объект {seen} выходит за чанк"
            break
        bank.hirc_types[obj_type] = bank.hirc_types.get(obj_type, 0) + 1
        seen += 1
        p += size
    bank.hirc_total = seen


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
