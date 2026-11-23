"""Кодеки изображений без обязательных зависимостей.

- QOI: декодер и кодер (спецификация qoi.h) — формат, в который GameMaker
  упаковывает часть текстурных страниц (иногда внутри BZ2).
- PNG: минимальный кодер RGBA8 (только для конвертации QOI→PNG).
- BZ2: обёртка с определением вложенного формата.
- Pillow подключается опционально — только для нарезки спрайтов.
"""
from __future__ import annotations

import bz2
import struct
import zlib

QOI_MAGIC = b"qoif"
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


# ---------------------------------------------------------------------------
# QOI
# ---------------------------------------------------------------------------

def is_qoi(data: bytes) -> bool:
    return data[:4] == QOI_MAGIC


def decode_qoi(data: bytes) -> tuple[int, int, bytes]:
    """QOI → (width, height, RGBA-байты). Бросает ValueError на битых данных."""
    if len(data) < 22 or data[:4] != QOI_MAGIC:
        raise ValueError("не QOI")
    w, h = struct.unpack(">II", data[4:12])
    if w == 0 or h == 0 or w * h > 200_000_000:
        raise ValueError(f"подозрительные размеры QOI: {w}x{h}")
    px = bytearray(w * h * 4)
    index = [(0, 0, 0, 0)] * 64
    r, g, b, a = 0, 0, 0, 255
    p = 14
    n = len(data)
    run = 0
    pos = 0
    total = w * h
    while pos < total:
        if run > 0:
            run -= 1
        else:
            if p >= n:
                raise ValueError("QOI: данные кончились")
            op = data[p]
            p += 1
            if op == 0xFE:  # RGB
                r, g, b = data[p], data[p + 1], data[p + 2]
                p += 3
            elif op == 0xFF:  # RGBA
                r, g, b, a = data[p], data[p + 1], data[p + 2], data[p + 3]
                p += 4
            elif op >> 6 == 0:  # INDEX
                r, g, b, a = index[op & 0x3F]
            elif op >> 6 == 1:  # DIFF
                r = (r + ((op >> 4) & 0x3) - 2) & 0xFF
                g = (g + ((op >> 2) & 0x3) - 2) & 0xFF
                b = (b + (op & 0x3) - 2) & 0xFF
            elif op >> 6 == 2:  # LUMA
                if p >= n:
                    raise ValueError("QOI: данные кончились (luma)")
                b1 = data[p]
                p += 1
                dg = (op & 0x3F) - 32
                r = (r + dg + ((b1 >> 4) & 0xF) - 8) & 0xFF
                g = (g + dg) & 0xFF
                b = (b + dg + (b1 & 0xF) - 8) & 0xFF
            else:  # RUN
                run = op & 0x3F
        idx = (r * 3 + g * 5 + b * 7 + a * 11) % 64
        index[idx] = (r, g, b, a)
        px[pos * 4: pos * 4 + 4] = bytes((r, g, b, a))
        pos += 1
    return w, h, bytes(px)


def encode_qoi(rgba: bytes, w: int, h: int) -> bytes:
    """RGBA-байты → QOI. Простая корректная реализация (RGBA-операции).

    Для конвертации PNG→QOI требуется декодированный RGBA (см. Pillow).
    """
    out = bytearray(QOI_MAGIC)
    out += struct.pack(">II", w, h)
    out += b"\x04\x00"  # 4 канала, sRGB
    index = [(0, 0, 0, 0)] * 64
    pr, pg, pb, pa = 0, 0, 0, 255
    run = 0
    total = w * h
    for i in range(total):
        r, g, b, a = rgba[i * 4: i * 4 + 4]
        if (r, g, b, a) == (pr, pg, pb, pa):
            run += 1
            if run == 62 or i == total - 1:
                out.append(0xC0 | (run - 1))
                run = 0
        else:
            if run:
                out.append(0xC0 | (run - 1))
                run = 0
            idx = (r * 3 + g * 5 + b * 7 + a * 11) % 64
            if index[idx] == (r, g, b, a):
                out.append(idx)
            elif a == pa:
                dr, dg, db = r - pr, g - pg, b - pb
                if -2 <= dr <= 1 and -2 <= dg <= 1 and -2 <= db <= 1:
                    out.append(0x40 | ((dr + 2) << 4) | ((dg + 2) << 2) | (db + 2))
                else:
                    dg = g - pg
                    dr_dg, db_dg = dr - dg, db - dg
                    if -32 <= dg <= 31 and -8 <= dr_dg <= 7 and -8 <= db_dg <= 7:
                        out.append(0x80 | (dg + 32))
                        out.append(((dr_dg + 8) << 4) | (db_dg + 8))
                    else:
                        out.append(0xFE)
                        out += bytes((r, g, b))
            else:
                out.append(0xFF)
                out += bytes((r, g, b, a))
            index[idx] = (r, g, b, a)
            pr, pg, pb, pa = r, g, b, a
    out += b"\x00" * 7 + b"\x01"
    return bytes(out)


# ---------------------------------------------------------------------------
# PNG (только кодирование RGBA8 — минимум для QOI→PNG)
# ---------------------------------------------------------------------------

def _png_chunk(tag: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + tag + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF))


def encode_png_rgba(rgba: bytes, w: int, h: int) -> bytes:
    stride = w * 4
    raw = bytearray()
    for y in range(h):
        raw.append(0)  # filter: none
        raw += rgba[y * stride:(y + 1) * stride]
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    return (PNG_MAGIC + _png_chunk(b"IHDR", ihdr)
            + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + _png_chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# BZ2 и определение вложенного формата
# ---------------------------------------------------------------------------

def bunzip_if_needed(payload: bytes) -> tuple[bytes, str]:
    """Если payload — BZ2, распаковать. Возвращает (данные, внутренний формат)."""
    if payload[:3] == b"BZh":
        try:
            inner = bz2.decompress(payload)
        except (OSError, ValueError):
            return payload, "bz2-broken"
        if inner[:4] == QOI_MAGIC:
            return inner, "bz2+qoi"
        if inner[:8] == PNG_MAGIC:
            return inner, "bz2+png"
        return inner, "bz2"
    if payload[:4] == QOI_MAGIC:
        return payload, "qoi"
    if payload[:8] == PNG_MAGIC:
        return payload, "png"
    return payload, "raw"


# ---------------------------------------------------------------------------
# Pillow (опционально): нарезка спрайтов/конвертации
# ---------------------------------------------------------------------------

def pillow():
    try:
        from PIL import Image  # type: ignore
        return Image
    except Exception:
        return None


def crop_png(png_bytes: bytes, x: int, y: int, w: int, h: int) -> bytes | None:
    """Вырезать прямоугольник из PNG (нужен Pillow). None, если Pillow недоступен."""
    Image = pillow()
    if Image is None or w <= 0 or h <= 0:
        return None
    import io
    try:
        with Image.open(io.BytesIO(png_bytes)) as im:
            im = im.convert("RGBA")
            if x < 0 or y < 0 or x + w > im.width or y + h > im.height:
                return None
            box = im.crop((x, y, x + w, y + h))
            buf = io.BytesIO()
            box.save(buf, "PNG")
            return buf.getvalue()
    except Exception:
        return None


def to_rgba(png_bytes: bytes) -> tuple[int, int, bytes] | None:
    Image = pillow()
    if Image is None:
        return None
    import io
    try:
        with Image.open(io.BytesIO(png_bytes)) as im:
            im = im.convert("RGBA")
            return im.width, im.height, im.tobytes()
    except Exception:
        return None
