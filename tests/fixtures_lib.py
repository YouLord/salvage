"""Библиотека сборки регресс-фикстур: маленькие «битые» игры на каждый баг.

Идея: у каждой регресс-фикстуры ровно одно отличие от рабочей — то, на котором
когда-то был баг. Собирать их общим кодом (а не копипастой) нужно, чтобы
фикстура не «поехала» вместе с кодом парсера: здесь только ручная сборка
байтов по спецификации из ROADMAP, без вызовов разбираемого кода.

Правила:
  * детерминизм: никакого random без seed, никакого времени/путей в байтах;
  * наружу отдаётся ``build(root)`` → Path и ``BUG_CASE`` с описанием;
  * все фикстуры регресса лежат в ``tests/fixtures/<engine>/regress_*``.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

MASK32 = 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Общие утилиты
# ---------------------------------------------------------------------------


def det_bytes(n: int, seed: str = "") -> bytes:
    """Детерминированные «случайные» байты."""
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:n])


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def write(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def png_stub(w: int, h: int, seed: str = "png") -> bytes:
    """Настоящий PNG с детерминированными пикселями."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        raw = struct.pack(">I", len(data)) + tag + data
        return raw + struct.pack(">I", zlib.crc32(tag + data) & MASK32)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    scanline = b"\x00" + det_bytes(w * 3, seed=f"{seed}:{w}x{h}")
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(scanline)) + chunk(b"IEND", b""))


def ogg_stub(n: int = 68) -> bytes:
    """Минимальный «OggS»-поток-заглушка (для проверки путей, не декодирования)."""
    return b"OggS" + det_bytes(max(0, n - 4), "ogg")


# ---------------------------------------------------------------------------
# data.win (GameMaker): сборка чанков руками
# ---------------------------------------------------------------------------


def gm_container(chunks: list[tuple[bytes, bytes]]) -> bytes:
    """FORM/DATA + чанки. Каждый чанк: tag + u32 len + payload (без паддинга)."""
    body = b"DATA" + b"".join(t + struct.pack("<I", len(p)) + p for t, p in chunks)
    return b"FORM" + struct.pack("<I", len(body)) + body


def gm_strg(strings: list[str], mode: str = "abs") -> bytes:
    """Чанк STRG: count, u32 offsets[], C-строки.

    ``mode``:
      * ``abs`` — абсолютные адреса файла (нужен base = позиция payload в файле);
      * ``rel_payload`` — офсеты относительно начала payload STRG;
    Для ``abs`` вызывающий обязан передать base через :func:`gm_strg_with_base`.
    """
    return gm_strg_with_base(strings, base=0, mode=mode)


def gm_strg_with_base(strings: list[str], base: int, mode: str = "abs") -> bytes:
    count = len(strings)
    header = 4 + 4 * count
    bodies = b"".join(s.encode("utf-8") + b"\x00" for s in strings)
    offs: list[int] = []
    cur = 0
    for s in strings:
        if mode == "abs":
            offs.append(base + header + cur)
        else:
            offs.append(header + cur)
        cur += len(s.encode("utf-8")) + 1
    return struct.pack("<I", count) + b"".join(struct.pack("<I", o) for o in offs) + bodies


def gm_tpag(entries: list[tuple[int, int, int, int, int]]) -> bytes:
    """TPAG: записи по 24 Б: 10×u16 (x,y,w,h, rx,ry,bx,by,bw,bh) + u32 tex."""
    out = bytearray()
    for (x, y, w, h, tex) in entries:
        out += struct.pack("<10H", x, y, w, h, 0, 0, 0, 0, w, h)
        out += struct.pack("<I", tex)
    assert len(out) % 24 == 0
    return bytes(out)


# ---------------------------------------------------------------------------
# RGSS (RPG Maker XP/VX/Ace)
# ---------------------------------------------------------------------------

RGSS_MAGIC = b"RGSSAD\x00"


def rgss_key_iter(start: int = 0xDEADCAFE):
    key = start
    while True:
        yield key
        key = (key * 7 + 3) & MASK32


def xor_words(data: bytes, key: int) -> bytes:
    """Симметричное шифрование v1: каждое слово (4 Б) XOR с ключом, ключ растёт."""
    out = bytearray()
    for i in range(0, len(data), 4):
        word = int.from_bytes(data[i:i + 4].ljust(4, b"\x00"), "little") ^ key
        out += word.to_bytes(4, "little")
        key = (key * 7 + 3) & MASK32
    return bytes(out[: len(data)])


def rgss_v1(files: list[tuple[str, bytes]], version_byte: int = 1) -> bytes:
    """Собрать RGSSAD v1-архив строго по раскладке парсера.

    Порядок в записи: [u32 len(имя)^k1][имя^k2][u32 размер^k3][данные^k4],
    где k1 — ключ на входе, k2 = k1*7+3, k3 = k2, продвинутый на число слов
    имени, k4 = k3*7+3. Данные занимают РОВНО size байт — паддинга в файле нет.
    """
    out = bytearray(RGSS_MAGIC + bytes([version_byte]))
    key = 0xDEADCAFE
    for name, payload in files:
        raw_name = name.encode("utf-8")
        k_len = key                                        # поле длины — текущим ключом
        k_name = (key * 7 + 3) & MASK32                    # байты имени — после advance
        k_size = k_name
        for _ in range((len(raw_name) + 3) // 4):
            k_size = (k_size * 7 + 3) & MASK32
        k_data = (k_size * 7 + 3) & MASK32
        out += struct.pack("<I", len(raw_name) ^ k_len)
        out += xor_words(raw_name.ljust(((len(raw_name) + 3) // 4) * 4, b"\x00"),
                         k_name)[:len(raw_name)]
        out += struct.pack("<I", len(payload) ^ k_size)
        padded = payload.ljust(((len(payload) + 3) // 4) * 4, b"\x00")
        out += xor_words(padded, k_data)[:len(payload)]
        key = k_data
        for _ in range((len(payload) + 3) // 4):
            key = (key * 7 + 3) & MASK32
    return bytes(out)


def rgss_v3(files: list[tuple[str, bytes]], seed: int = 0x12345678) -> bytes:
    """Собрать RGSSAD v3 (Ace) строго по эталону (rpga, rpgtools, taroxd).

    Раскладка файла: [8 байт magic][seed u32] затем ВЕСЬ индекс подряд:
    запись = [offset][size][file_key][name_len] (каждое ^ key) + имя (^ key
    побайтово), и только ПОСЛЕ индекса — данные по абсолютным offset.
    Ключ индекса: key = seed*9+3 (seed хранится как есть, без XOR).
    """
    key = (seed * 9 + 3) & MASK32
    keybytes = key.to_bytes(4, "little")

    def enc_name(raw: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(
            raw, (keybytes * ((len(raw) + 3) // 4))[:len(raw)]))

    header_len = len(RGSS_MAGIC) + 1 + 4
    index = bytearray()
    data_blob = bytearray()
    for name, payload in files:
        raw_name = name.encode("utf-8")
        file_key = int.from_bytes(hashlib.sha256(raw_name).digest()[:4], "little")
        data_offset = header_len + 0  # заполним после сборки индекса
        index += struct.pack("<IIII", 0, len(payload) ^ key,
                             file_key ^ key, len(raw_name) ^ key)
        index += enc_name(raw_name)
        data_blob += xor_words(
            payload.ljust(((len(payload) + 3) // 4) * 4, b"\x00"), file_key)[:len(payload)]
    # вторая проходка: подставить настоящие абсолютные адреса данных
    blob = bytearray(index)
    pos = 0
    data_start = header_len + len(index)
    out_index = bytearray()
    cursor = data_start
    for i, (name, payload) in enumerate(files):
        raw_name = name.encode("utf-8")
        file_key = int.from_bytes(hashlib.sha256(raw_name).digest()[:4], "little")
        out_index += struct.pack("<IIII", cursor ^ key, len(payload) ^ key,
                                 file_key ^ key, len(raw_name) ^ key)
        out_index += enc_name(raw_name)
        cursor += len(payload)
    return bytes(RGSS_MAGIC + b"\x03" + struct.pack("<I", seed)
                 + bytes(out_index) + bytes(data_blob))


# ---------------------------------------------------------------------------
# Unreal .pak v10 (FDI-битфилд записи)
# ---------------------------------------------------------------------------

PAK_MAGIC = 0x5A6F12E1


V3_ENTRY_HEADER = 53     # offset(8) size(8) unc(8) method(4) sha1(20) enc(1) block_size(4)


def unreal_pak_v10(files: list[tuple[str, bytes]], *, mount: str = "../../../\x00") -> bytes:
    """Собрать .pak версии 10 так, как его читает парсер.

    Раскладка (сверено с rust-u4pak src/index.rs, record.rs, unpack.rs):
      файл:        { [заголовок записи 53 Б][данные] }* , затем индекс, FDI, footer
      индекс v10:  mount | i32 count | u64 path_hash_seed | u32 has_path_hash
                   | u32 has_fdi | i64 fdi_off | i64 fdi_size | sha1[20]
                   | i32 enc_size | encoded_record_info | u32 file_count
      FDA:         u32 dir_count { fstring dir, u32 file_count
                                  { fstring name, u32 enc_off } }
      запись v10:  u32 битфилд (0-5 block_size(<<11), 6-21 block_count,
                   22 encrypted, 23-28 метод, 29 size32, 30 unc32, 31 off32)
                   + offset + uncompressed (+ size, если метод != 0)
                   + [u32 размер блока на блок], если блоков > 1 или шифрование

    ``offset`` записи указывает на её ЗАГОЛОВОК В ФАЙЛЕ (не на данные) — это
    ключевой инвариант pak, на котором исторически был баг. Данные лежат
    сразу после 53-байтного заголовка. Блоков здесь нет (метод 0).
    """
    blob = bytearray()
    records: list[tuple[str, int, int]] = []      # имя, offset заголовка, размер
    for name, payload in files:
        header_off = len(blob)
        header = struct.pack("<QQQI", header_off, len(payload), len(payload), 0)
        header += b"\x00" * 20                     # sha1 (не проверяем)
        header += b"\x00"                          # encrypted
        header += struct.pack("<I", 65536)          # block_size
        assert len(header) == V3_ENTRY_HEADER, len(header)
        blob += header
        blob += payload
        records.append((name, header_off, len(payload)))

    # encoded_record_info: компактные записи; FDI ссылается на смещения в них
    encoded = bytearray()
    enc_offsets: dict[str, int] = {}
    for name, offset, size in records:
        enc_offsets[name] = len(encoded)
        # off32/unc32 — иначе парсер ждёт 64-битные поля
        bits = (0 << 0) | (0 << 6) | (0 << 22) | (0 << 23) | (0 << 29) | (1 << 30) | (1 << 31)
        encoded += struct.pack("<I", bits)
        encoded += struct.pack("<I", offset)
        encoded += struct.pack("<I", size)

    dirs: dict[str, list[tuple[str, int]]] = {}
    for name, offset, size in records:
        head, _, tail = name.rpartition("/")
        dirs.setdefault(head, []).append((tail, enc_offsets[name]))
    fdi = bytearray(struct.pack("<I", len(dirs)))
    for dir_name, items in sorted(dirs.items()):
        raw_dir = (dir_name + "/").encode("utf-8") + b"\x00" if dir_name else b"/\x00"
        fdi += struct.pack("<i", len(raw_dir)) + raw_dir
        fdi += struct.pack("<I", len(items))
        for tail, off in items:
            raw_name = tail.encode("utf-8") + b"\x00"
            fdi += struct.pack("<i", len(raw_name)) + raw_name + struct.pack("<I", off)

    mount_b = mount.encode("utf-8") if isinstance(mount, str) else mount
    index = bytearray()
    index += struct.pack("<i", len(mount_b)) + mount_b
    index += struct.pack("<i", 0)                  # legacy count (для v10 = 0)
    index += struct.pack("<Q", 0)                  # path hash seed
    index += struct.pack("<I", 0)                  # has_path_hash
    index += struct.pack("<I", 1)                  # has_fdi
    fdi_offset = len(blob) + len(index) + 16 + 20 + 4 + len(encoded) + 4
    index += struct.pack("<qq", fdi_offset, len(fdi))
    index += b"\x00" * 20                         # fdi sha1
    index += struct.pack("<i", len(encoded))
    index += bytes(encoded)
    index += struct.pack("<I", 0)                  # file_count (legacy records)

    data_len = len(blob)
    blob += index
    blob += fdi
    footer = struct.pack("<II", PAK_MAGIC, 10)
    footer += struct.pack("<QQ", data_len, len(index))
    footer += b"\x00" * 20
    footer += b"".join(n.ljust(32, b"\x00")
                       for n in (b"Zlib", b"LZ4", b"Oodle", b"None", b""))
    return bytes(blob) + footer


# ---------------------------------------------------------------------------
# Ren'Py: .rpyc с сигнатурой под версию
# ---------------------------------------------------------------------------


def rpyc_blob(source_name: str, payload: bytes, *, legacy: bool = True) -> bytes:
    """Минимальный rpyc-стаб: имя исходника + бинарная нагрузка (не Marhsal-64)."""
    name = source_name.encode("utf-8") + b"\x00"
    if legacy:
        # старый формат: '\x00' + u32 длина имени + имя + '\x00' + нагрузка
        return b"\x00" + struct.pack("<I", len(name)) + name + b"\x00" + payload
    return name + struct.pack("<I", len(payload)) + payload


def write_expected(root: Path, name: str, data: dict) -> Path:
    """expected-файл как стабильный JSON (сортировка ключей, без пробелов-«красоты»)."""
    import json
    text = json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True)
    return write(root / name, (text + "\n").encode("utf-8"))
