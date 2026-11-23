"""Unreal Engine .pak: чтение footer, индекса (v1–v11), записей и блоков.

Поддерживаем:
  * версии 1–11 (собственная таблица footer'ов и записей, сверена на реальных паках);
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


# Legacy ECompressionFlags для pak v1–v7: поле записи — это БИТЫ алгоритма,
# а не индекс. Для v8+ то же поле — 0-based индекс в массиве имён методов
# из footer (0 — «нет сжатия»); это сверено на практике (см. ROADMAP).
LEGACY_METHODS = {
    0x00: "none",
    0x01: "zlib",
    0x02: "gzip",
    0x04: "custom",     # движок игры подставляет свой кодек, часто Oodle
    0x10: "bias-memory",
    0x20: "bias-speed",
}


@dataclass
class PakEntry:
    name: str
    offset: int
    size: int
    uncompressed: int
    method: int = 0
    encrypted: bool = False
    blocks: list[tuple[int, int]] = field(default_factory=list)

    # Имя метода: 0 — без сжатия, 1 — zlib; остальные индексы ссылаются на
    # таблицу имён из footer (v8+), поэтому «0x10» само по себе ничего не значит.
    compression_name: str = ""
    header_size: int = 0        # размер сериализованного заголовка записи в индексе
    #: Размер заголовка записи В ФАЙЛЕ — он больше, чем в индексе.
    #: Для v1–v9 совпадает с header_size; для v10+ файловый заголовок —
    #: 53 байта + 16 на блок (+4 при блоке) против компактной записи в индексе.
    file_header_size: int = 0

    @property
    def data_offset(self) -> int:
        """Данные начинаются ПОСЛЕ заголовка записи (offset указывает на заголовок).

        Важно: прибавлять надо РАЗМЕР ЗАГОЛОВКА В ФАЙЛЕ, а не длину записи в
        индексе — у v10+ это разные числа (сверено с rust-u4pak unpack.rs:
        ``start_offset = record.offset() + header_size``).
        """
        return self.offset + (self.file_header_size or self.header_size)

    @property
    def compression(self) -> str:
        """Имя метода (как в footer) или 0xNN, если имя не распознано."""
        if self.method == 0:
            return "none"
        if self.compression_name:
            return self.compression_name
        return f"0x{self.method:x}"


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


def _table_is_zero_based(compression_names: list[str]) -> bool:
    """Есть ли в таблице явный нулевой слот «None» (тогда имена идут с нуля).

    Это свойство самой таблицы, поэтому решается детерминированно и
    одинаково для всех записей пака — без догадок по отдельным записям.
    """
    return bool(compression_names) and \
        (compression_names[0] or "").strip().lower() in ("none", "-", "")


def method_name(method: int, compression_names: list[str], version: int) -> str:
    """Каноническое имя метода сжатия (lowercase) или '' если не распознан.

    Две конвенции поля method, обе зафиксированы тестами:
      * v1–v7 — legacy-биты ECompressionFlags: 0 none, 1 zlib, 2 gzip,
        4 custom, 0x10 bias-memory, 0x20 bias-speed. Это НЕ индексы.
      * v8+ — индекс в таблице имён из footer. Основная конвенция 1-based:
        method=1 → names[0] (в таблице 5 слотов, нулевой слот «нет сжатия»
        подразумевается). Если же в names[0] явно написано «None»/«-»,
        таблица нумеруется с нуля: method → names[method].
    """
    if method == 0:
        return "none"
    if version >= 8:
        if not compression_names:
            return ""
        if _table_is_zero_based(compression_names):
            if method < len(compression_names):
                return (compression_names[method] or "").strip().lower()
            return ""
        idx = method - 1
        if 0 <= idx < len(compression_names):
            return (compression_names[idx] or "").strip().lower()
        return ""
    if method in LEGACY_METHODS:
        return LEGACY_METHODS[method]
    return ""


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
            # от magic: +4 version, +8 index offset, +8 index size, +20 sha1 = +44
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
        # v10+: FDI (Full Directory Index) — отдельный блок ФАЙЛА, ссылки на него
        # абсолютные (сверено с rust-u4pak src/index.rs). Читаем его здесь.
        fdi_blob = b""
        if version >= 10:
            try:
                fdi_off, fdi_size = _peek_fdi_bounds(index)
            except (struct.error, IndexError):
                fdi_off = fdi_size = 0
            if fdi_size > 0 and fdi_off + fdi_size <= path.stat().st_size:
                f.seek(fdi_off)
                fdi_blob = f.read(fdi_size)
        mount, entries = _parse_index(index, version, fdi_blob)
        # Имя метода: v8+ — 0-based индекс в compression_names (0 = «нет сжатия»,
        # поэтому именам соответствуют индексы 1..N-1); v1–v7 — legacy-биты.
        for e in entries:
            e.compression_name = method_name(e.method, compression_names, version)
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
    start_p = p
    if p + 28 > len(buf):
        raise PakError("индекс обрезан: нет заголовка записи")
    offset, size, unc, method = struct.unpack_from("<QQQI", buf, p)
    p += 28
    # поля проверяем до чтения блоков/хвоста: битый индекс не должен
    # приводить к «правдоподобным» записям (это тихо неправильный результат).
    total = len(buf)
    if offset > (1 << 40) or size > (1 << 40) or unc > (1 << 40):
        raise PakError("индекс обрезан/повреждён: размеры записи вне разумных пределов")
    if version <= 1:
        p += 8  # timestamp
    p += 20  # sha1
    blocks: list[tuple[int, int]] = []
    encrypted = False
    if version >= 3:
        block_count = 0
        if method != 0:
            if p + 4 > total:
                raise PakError("индекс обрезан: нет block count")
            block_count = struct.unpack_from("<I", buf, p)[0]
            p += 4
            if block_count > 1 << 20:
                raise PakError("индекс повреждён: слишком много блоков")
            for _ in range(block_count):
                start, end = struct.unpack_from("<QQ", buf, p)
                blocks.append((start, end))
                p += 16
        encrypted = buf[p] == 1
        p += 1
        p += 4  # block size
    if version >= 4:
        p += 1  # unknown
    # Файловый заголовок = ПОЛНЫЙ размер (53 + блоки), а p-start_p — это лишь
    # длина компактной записи в индексе; складывать их нельзя (дало бы 65 вместо 53).
    file_header_size = _v10_file_tail(method, blocks, encrypted)
    return PakEntry(name="", offset=offset, size=size, uncompressed=unc,
                    method=method, encrypted=encrypted, blocks=blocks,
                    header_size=p - start_p, file_header_size=file_header_size), p


def _peek_fdi_bounds(index: bytes) -> tuple[int, int]:
    """Достать (offset, size) блока FDI из заголовка индекса v10+."""
    p = 0
    _, p = _read_fstring(index, p)
    p += 4          # entry count
    p += 8          # path hash seed
    has_path_hash = struct.unpack_from("<I", index, p)[0]
    p += 4
    if has_path_hash:
        p += 8 + 8 + 20
    has_fdi = struct.unpack_from("<I", index, p)[0]
    p += 4
    if not has_fdi:
        return 0, 0
    fdi_off, fdi_size = struct.unpack_from("<qq", index, p)
    return fdi_off, fdi_size


def _parse_index(index: bytes, version: int,
                 fdi_blob: bytes = b"") -> tuple[str, list[PakEntry]]:
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
        # FDI — отдельный блок: либо внутри буфера индекса, либо (обычно) в файле.
        if fdi_offset + fdi_size <= len(index):
            buf, base = index, fdi_offset
        elif fdi_blob:
            buf, base = fdi_blob, 0
        else:
            buf, base = b"", 0
        if buf:
            try:
                entries = _parse_fdi(buf, base, enc_start, enc_size, index)
            except (struct.error, IndexError):
                entries = []
    return mount, entries


def _parse_fdi(buf: bytes, p: int, enc_start: int, enc_size: int,
               enc_buf: bytes | None = None) -> list[PakEntry]:
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
                e = decode_encoded_entry(enc_buf if enc_buf is not None else buf,
                                         enc_start + enc_off)
            except struct.error:
                continue
            e.name = full.lstrip("/")
            entries.append(e)
    return entries


V3_RECORD_HEADER_SIZE = 53      # offset(8)+size(8)+unc(8)+method(4)+sha1(20)+enc(1)+block_size(4)


def _v10_file_tail(method: int, blocks: list[tuple[int, int]], encrypted: bool) -> int:
    """Размер файлового заголовка записи для v10+ (сверено с rust-u4pak pak.rs).

    pak.rs::header_size для версий ≥ 3: базовые 53 байта (offset, size,
    uncompressed, method, sha1, encrypted, block_size); если у записи есть
    блоки сжатия — ещё 4 байта (block count) и по 16 на блок.
    Компактная запись в ИНДЕКСЕ короче, поэтому здесь считается разница.
    """
    if method == 0:
        return V3_RECORD_HEADER_SIZE
    count = max(1, len(blocks))
    return V3_RECORD_HEADER_SIZE + 4 + 16 * count


def decode_encoded_entry(buf: bytes, p: int) -> PakEntry:
    """Encoded entry (v10+): битовое поле + переменные поля."""
    start_p = p
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
    # Файловый заголовок = ПОЛНЫЙ размер (53 + блоки), а p-start_p — это лишь
    # длина компактной записи в индексе; складывать их нельзя (дало бы 65 вместо 53).
    file_header_size = _v10_file_tail(method, blocks, encrypted)
    return PakEntry(name="", offset=offset, size=size, uncompressed=unc,
                    method=method, encrypted=encrypted, blocks=blocks,
                    header_size=p - start_p, file_header_size=file_header_size)


# ---------------------------------------------------------------------------
# Извлечение
# ---------------------------------------------------------------------------

def _block_decompress(chunk: bytes, name: str,
                      expected: int | None) -> tuple[bytes | None, str]:
    """Распаковать один блок по имени метода. Возвращает (данные, статус).

    Метод уже разрешён (method_name) — здесь никаких догадок по номеру:
    неизвестный метод обязан стать ошибкой, а не «данными как есть».
    """
    lowered = (name or "").lower()
    if lowered == "none":
        return chunk, "ok"
    if not lowered:
        return None, "compression:unknown"
    if lowered in ("zlib", "gzip"):
        try:
            return zlib.decompress(chunk), "ok"
        except zlib.error as exc:
            return None, f"error:{lowered}:{exc}"
    if "lz4" in lowered:
        from ...core import lz4 as lz4block
        try:
            return lz4block.decompress_block(chunk, expected or None), "ok"
        except lz4block.Lz4BlockError as exc:
            return None, f"error:lz4:{exc}"
    if any(k in lowered for k in ("oodle", "kraken", "mermaid", "selkie", "leviathan")):
        # Oodle лицензирован и в чистом Python не декодируется: честный статус
        return None, "compression:oodle"
    if "zstd" in lowered:
        try:
            import zstandard  # type: ignore
            return zstandard.ZstdDecompressor().decompress(chunk), "ok"
        except Exception:
            return None, "unsupported:zstd-python-missing"
    return None, f"compression:{lowered or 'unknown'}"


def read_entry_data(pak: PakFile, e: PakEntry, max_bytes: int = 64 << 20) -> tuple[bytes | None, str]:
    """Прочитать данные записи. Возвращает (данные, статус).

    Статусы: "ok", "encrypted", "unsupported:<метод>", "compression:<метод>",
    "error:<причина>". Никогда не возвращает «похожие на данные» байты при ошибке.
    """
    if e.encrypted:
        return None, "encrypted"
    name = e.compression_name or method_name(e.method, pak.compression_names, pak.version)
    if e.method != 0 and not name:
        # имя метода неизвестно: отдавать байты «как есть» нельзя — это тихо
        # неправильный результат, а не данные.
        return None, f"compression:0x{e.method:x}"
    base = e.data_offset
    try:
        with open(pak.path, "rb") as f:
            if e.method == 0:
                f.seek(base)
                return f.read(min(e.size, max_bytes)), "ok"
            out = bytearray()
            if e.blocks and any(b_end for _, b_end in e.blocks):
                # v3–v9: явные (start,end) — АБСОЛЮТНЫЕ смещения в файле
                for start, end in e.blocks:
                    f.seek(start)
                    chunk = f.read(max(0, end - start))
                    part, status = _block_decompress(chunk, name,
                                                     _per_block_hint(e, len(e.blocks)))
                    if part is None:
                        return None, status
                    out += part
                    if len(out) > max_bytes:
                        break
            elif e.blocks:
                # v10+: блоки без смещений. Формат UE:
                #   при block_count > 1 каждый блок: [uint32 csize][данные]
                #   при block_count == 1: сплошной поток
                block_size = e.blocks[0][0] or 65536
                f.seek(base)
                remaining = e.size
                per = _per_block_hint(e, len(e.blocks)) if len(e.blocks) > 1 else e.uncompressed
                while remaining > 0:
                    if len(e.blocks) > 1:
                        head = f.read(4)
                        if len(head) < 4:
                            return None, "error:truncated-block"
                        csize = struct.unpack("<I", head)[0]
                        chunk = f.read(csize)
                        remaining -= 4 + csize
                    else:
                        chunk = f.read(remaining)
                        remaining = 0
                    part, status = _block_decompress(chunk, name, per)
                    if part is None:
                        return None, status
                    out += part
                    if len(out) > max_bytes:
                        break
            else:
                f.seek(base)
                chunk = f.read(min(e.size, max_bytes))
                part, status = _block_decompress(chunk, name, e.uncompressed)
                if part is None:
                    return None, status
                out += part
            return bytes(out[:max_bytes]), "ok"
    except OSError as exc:
        return None, f"error:{exc}"


def _per_block_hint(e: PakEntry, count: int) -> int | None:
    """Ожидаемый размер распаковки одного блока (для LZ4 без store_size)."""
    if count <= 0:
        return e.uncompressed or None
    if count == 1:
        return e.uncompressed or None
    # последний блок может быть короче; берём типичный размер блока
    block = e.blocks[0][0] if e.blocks else 0
    return block or (e.uncompressed // count if e.uncompressed else None)
