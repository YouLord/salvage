"""LZ4 block-формат: чистый Python-декодер (без обязательных зависимостей).

Поддерживается именно block-формат (как в Unreal .pak и Wwise), а не frame:
  последовательность = token, literals, offset(u16le), match,
  token = (literal_len << 4) | (match_len - 4); 15 — сигнал «дочитать байтами 255».

Декодер намеренно строгий: любое нарушение границ — Lz4BlockError, а не
«похожие байты». Это лучше, чем тихо вернуть мусор под видом данных.
"""
from __future__ import annotations

__all__ = ["Lz4BlockError", "decompress_block", "available"]

LZ4_MIN_MATCH = 4


class Lz4BlockError(ValueError):
    """Блок не является корректным LZ4 block-потоком."""


def available() -> bool:
    """Есть ли быстрый внешний декодер (только для сверки, не обязателен)."""
    try:
        import lz4.block  # noqa: F401
        return True
    except Exception:
        return False


def _read_len(src: bytes, pos: int, base: int) -> tuple[int, int]:
    """Дочитать длину: 15 + сумма байтов по 255 (последний < 255)."""
    total = base
    if base < 15:
        return total, pos
    while True:
        if pos >= len(src):
            raise Lz4BlockError("обрезано: длина выходит за границу блока")
        b = src[pos]
        pos += 1
        total += b
        if b != 255:
            return total, pos


def decompress_block(src: bytes, expected_size: int | None = None) -> bytes:
    """Распаковать LZ4 block. expected_size — если известен (из записи .pak)."""
    src = bytes(src)
    out = bytearray()
    pos = 0
    n = len(src)
    if n == 0:
        if expected_size:
            raise Lz4BlockError("пустой блок при известном размере")
        return b""

    while pos < n:
        token = src[pos]
        pos += 1

        lit_len, pos = _read_len(src, pos, token >> 4)
        if pos + lit_len > n:
            raise Lz4BlockError("literals выходят за границу блока")
        out += src[pos:pos + lit_len]
        pos += lit_len

        # последняя последовательность состоит только из literals
        if pos >= n:
            break

        if pos + 2 > n:
            raise Lz4BlockError("обрезано: нет offset у match")
        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        if offset == 0:
            raise Lz4BlockError("offset = 0 недопустим")
        if offset > len(out):
            raise Lz4BlockError(f"offset {offset} больше уже распакованного ({len(out)})")

        match_len, pos = _read_len(src, pos, token & 0x0F)
        match_len += LZ4_MIN_MATCH
        start = len(out) - offset
        # перекрывающиеся копии — легальны, копируем побайтово
        for i in range(match_len):
            out.append(out[start + i])

        if expected_size is not None and len(out) > expected_size:
            raise Lz4BlockError(
                f"распаковка превысила ожидаемый размер: {len(out)} > {expected_size}")

    if expected_size is not None and len(out) != expected_size:
        raise Lz4BlockError(
            f"размер не совпал: получено {len(out)}, ожидалось {expected_size}")
    return bytes(out)
