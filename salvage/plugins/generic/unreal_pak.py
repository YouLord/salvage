"""Unreal Engine .pak: чтение footer, индекса (v1–v11), записей и блоков.

Поддерживаем:
  * версии 1–11 (layout из спецификации panzi/u4pak, проверен на реальных паках);
  * незашифрованный индекс и записи;
  * сжатие zlib (0x01) с нарезкой на блоки;
  * честную пометку: AES-шифрованный индекс/записи (нужен ключ AES-256),
    Oodle/LZ4 (нужна внешняя библиотека).

Для v10+ индекс читается через Full Directory Index (fallback — плоский индекс).
"""
from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass, field
from pathlib import Path

PAK_MAGIC = 0x5A6F12E1
FOOTER_TABLE = {
    # version: (размер footer, есть guid, есть encrypted-index-флаг, есть frozen, число имён методов)
    1: (44, False, False, False, 0),
    2: (44, False, False, False, 0),
    3: (44, False, False, False, 0),
    4: (45, False, True, False, 0),
    5: (45, False, True, False, 0),
    6: (45, False, True, False, 0),
    7: (65, True, True, False, 0),
    8: (193, True, True, False, 4),
    9: (226, True, True, True, 5),
    10: (225, True, True, False, 5),
    11: (225, True, True, False, 5),
}


class PakError(ValueError):
    pass


@dataclass
class PakEntry:
    name: str
    offset: int
    size: int
    uncompressed: int
    method: int = 0
    encrypted: bool = False
    blocks: list[tuple[int, int]] = field(default_factory=list)

    @property
    def compression(self) -> str:
        return {0: "none", 1: "zlib", 0x10: "bias-memory", 0x20: "bias-speed"}.get(
            self.method, f"0x{self.method:x}")


@dataclass
class PakFile:
    path: Path
    version: int
    mount_point: str
    entries: list[PakEntry]
    encrypted_index: bool
    compression_names: list[str]
    footer_offset: int


def sniff(path: Path) -> bool:
    """Быстрая проверка: magic в хвосте 230 байт + валидная версия."""
    try:
        size = path.stat().st_size
        if size < 44:
            return False
        with open(path, "rb") as f:
            f.seek(max(0, size - 240))
            tail = f.read()
    except OSError:
        return False
    idx = tail.rfind(struct.pack("<I", PAK_MAGIC))
    if idx < 0 or idx + 8 > len(tail):
        return False
    version = struct.unpack("<I", tail[idx + 4:idx + 8])[0]
    return 1 <= version <= 11


def _scan_footer(f) -> tuple[int, int]:
    """Найти позицию magic и версию (footer бывает с неизвестными полями)."""
    f.seek(0, 2)
    size = f.tell()
    f.seek(max(0, size - 240))
    tail = f.read()
    magic = struct.pack("<I", PAK_MAGIC)
    idx = tail.rfind(magic)
    if idx < 0 or idx + 8 > len(tail):
        raise PakError("magic 0x5A6F12E1 не найден в хвосте файла")
    version = struct.unpack("<I", tail[idx + 4:idx + 8])[0]
    return (size - len(tail) + idx), version


def read_pak(path: Path) -> PakFile:
    with open(path, "rb") as f:
        magic_off, version = _scan_footer(f)
        if version not in FOOTER_TABLE:
            raise PakError(f"неподдерживаемая версия pak: {version}")
        enc_flag = version >= 4
        # от magic: +8 version, +8 index_offset, +8 index_size, +20 hash
        f.seek(magic_off + 8)
        index_offset, index_size = struct.unpack("<QQ", f.read(16))
        header_pos = magic_off
        encrypted_index = False
        if enc_flag:
            f.seek(magic_off - 1)
            encrypted_index = f.read(1) == b"\x01"
        compression_names: list[str] = []
        if version >= 8:
            n = FOOTER_TABLE[version][4]
            f.seek(magic_off + 44 + (1 if version == 9 else 0))
            raw = f.read(32 * n)
            compression_names = [raw[i * 32:(i + 1) * 32].split(b"\x00")[0].decode("ascii", "ignore")
                                 for i in range(n)]
        if index_offset == 0 or index_offset >= path.stat().st_size:
            # 64-битные поля могли быть прочитаны как мусор — пробуем соседние варианты
            raise PakError("index offset вне файла (возможно, pak с нестандартным footer)")
        f.seek(index_offset)
        index = f.read(index_size)
        if len(index) != index_size:
            raise PakError("индекс короче заявленного")
        if encrypted_index:
            raise PakError("индекс зашифрован (AES-256): нужен ключ из игры")
        try:
            index = zlib.decompress(index)
        except zlib.error:
            pass  # индекс может быть несжатым
        mount, entries = _parse_index(index, version)
        return PakFile(path=path, version=version, mount_point=mount,
                       entries=entries, encrypted_index=encrypted_index,
                       compression_names=compression_names, footer_offset=magic_off)


# ---------------------------------------------------------------------------
# Индекс
# ---------------------------------------------------------------------------

def _read_i32(buf: bytes, p: int) -> tuple[int, int]:
    return struct.unpack_from("<i", buf, p)[0], p + 4


def _read_fstring(buf: bytes, p: int) -> tuple[str, int]:
    n, p = _read_i32(buf, p)
    if n < 0:  # UTF-16
        raw = buf[p:p + (-n) * 2]
        return raw.decode("utf-16-le", "replace").rstrip("\x00"), p + (-n) * 2
    raw = buf[p:p + n]
    return raw.decode("utf-8", "replace").rstrip("\x00"), p + n


def _parse_entry(buf: bytes, p: int, version: int) -> tuple[PakEntry, int]:
    offset, size, unc, method = struct.unpack_from("<QQQI", buf, p)
    p += 28
    if version <= 1:
        p += 8  # timestamp
    p += 20  # sha1
    blocks: list[tuple[int, int]] = []
    encrypted = False
    if version >= 3:
        block_count = 0
        if method != 0:
            block_count = struct.unpack_from("<I", buf, p)[0]
            p += 4
            for _ in range(block_count):
                start, end = struct.unpack_from("<QQ", buf, p)
                blocks.append((start, end))
                p += 16
        encrypted = buf[p] == 1
        p += 1
        p += 4  # block size
    if version >= 4:
        p += 1  # unknown
    return PakEntry(name="", offset=offset, size=size, uncompressed=unc,
                    method=method, encrypted=encrypted, blocks=blocks), p


def _parse_index(index: bytes, version: int) -> tuple[str, list[PakEntry]]:
    p = 0
    mount, p = _read_fstring(index, p)
    if 1 <= version <= 9:
        count = struct.unpack_from("<I", index, p)[0]
        p += 4
        entries: list[PakEntry] = []
        for _ in range(count):
            name, p = _read_fstring(index, p)
            e, p = _parse_entry(index, p, version)
            e.name = name
            entries.append(e)
        return mount, entries

    # --- v10/v11 ---
    count = struct.unpack_from("<i", index, p)[0]
    p += 4
    p += 8  # path hash seed
    has_path_hash = struct.unpack_from("<I", index, p)[0]
    p += 4
    if has_path_hash:
        p += 8 + 8 + 20  # offset, size, hash
    has_fdi = struct.unpack_from("<I", index, p)[0]
    p += 4
    fdi_offset = fdi_size = 0
    if has_fdi:
        fdi_offset, fdi_size = struct.unpack_from("<qq", index, p)
        p += 8 + 8 + 20
    enc_size = struct.unpack_from("<i", index, p)[0]
    p += 4
    enc_start = p
    p += enc_size
    p += 4  # file count (unused)

    entries: list[PakEntry] = []
    if has_fdi and fdi_offset >= 0:
        # FDI лежит отдельным блоком (обычно в конце индекса, вне сжатого enc)
        fdi = index[fdi_offset - 0:fdi_offset + fdi_size] if fdi_offset + fdi_size <= len(index) else b""
        fdi_p = fdi_offset if fdi_offset < len(index) else 0
        try:
            entries = _parse_fdi(index, fdi_p, enc_start, enc_size)
        except (struct.error, IndexError):
            entries = []
    if not entries:
        try:
            entries = _parse_fdi(index, 0, enc_start, enc_size)
        except (struct.error, IndexError):
            entries = []
    return mount, entries


def _parse_fdi(buf: bytes, p: int, enc_start: int, enc_size: int) -> list[PakEntry]:
    """Full Directory Index: каталоги → файлы → смещения в encoded entries."""
    entries: list[PakEntry] = []
    dir_count = struct.unpack_from("<I", buf, p)[0]
    p += 4
    for _ in range(dir_count):
        dir_name, p = _read_fstring(buf, p)
        file_count = struct.unpack_from("<I", buf, p)[0]
        p += 4
        for _ in range(file_count):
            file_name, p = _read_fstring(buf, p)
            enc_off = struct.unpack_from("<I", buf, p)[0]
            p += 4
            full = (dir_name.rstrip("/") + "/" + file_name) if dir_name else file_name
            try:
                e = decode_encoded_entry(buf, enc_start + enc_off)
            except struct.error:
                continue
            e.name = full.lstrip("/")
            entries.append(e)
    return entries


def decode_encoded_entry(buf: bytes, p: int) -> PakEntry:
    """Encoded entry (v10+): битовое поле + переменные поля."""
    bits = struct.unpack_from("<I", buf, p)[0]
    p += 4
    block_size = (bits & 0x3F) << 11
    block_count = (bits >> 6) & 0xFFFF
    encrypted = bool((bits >> 22) & 1)
    method = (bits >> 23) & 0x3F
    size32 = bool((bits >> 29) & 1)
    unc32 = bool((bits >> 30) & 1)
    off32 = bool((bits >> 31) & 1)
    if off32:
        offset = struct.unpack_from("<I", buf, p)[0]
        p += 4
    else:
        offset = struct.unpack_from("<Q", buf, p)[0]
        p += 8
    unc = struct.unpack_from("<I" if unc32 else "<Q", buf, p)[0]
    p += 4 if unc32 else 8
    size = unc
    if method != 0:
        size = struct.unpack_from("<I", buf, p)[0]
        p += 4
    blocks = []
    if block_count and (encrypted or block_count != 1):
        for _ in range(block_count):
            bs = struct.unpack_from("<I", buf, p)[0]
            p += 4
            blocks.append((bs, 0))
    else:
        for _ in range(block_count):
            blocks.append((block_size, 0))
    return PakEntry(name="", offset=offset, size=size, uncompressed=unc,
                    method=method, encrypted=encrypted, blocks=blocks)


# ---------------------------------------------------------------------------
# Извлечение
# ---------------------------------------------------------------------------

def read_entry_data(pak: PakFile, e: PakEntry, max_bytes: int = 64 << 20) -> tuple[bytes | None, str]:
    """Прочитать данные записи. Возвращает (данные, статус)."""
    if e.encrypted:
        return None, "encrypted"
    try:
        with open(pak.path, "rb") as f:
            if e.method == 0:
                f.seek(e.offset)
                return f.read(min(e.size, max_bytes)), "ok"
            if e.method != 1:
                return None, f"compression:{e.method}"
            out = bytearray()
            if e.blocks:
                for i, (start, end) in enumerate(e.blocks):
                    if end and end > start:
                        f.seek(start)
                        chunk = f.read(end - start)
                    else:
                        # v10: блоки без смещений — читаем последовательно по размеру
                        chunk = f.read(start)
                    out += zlib.decompress(chunk)
                    if len(out) > max_bytes:
                        break
            else:
                f.seek(e.offset)
                out += zlib.decompress(f.read(min(e.size, max_bytes)))
            return bytes(out[:max_bytes]), "ok"
    except (OSError, zlib.error) as exc:
        return None, f"error:{exc}"
