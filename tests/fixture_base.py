"""Абстрактный контракт генератора фикстур.

Каждый движок/формат — отдельный модуль ``make_fixture_<name>.py`` с функцией
``build(root, *, with_bug: bool = False) -> None``.

Правило из ТЗ: **на каждый исправленный баг — минимальная фикстура**, которая
падала бы до фикса и проходит после. Режим ``with_bug=True`` (CLI: ``--кейс
<name>``) собирает именно такую «плохую» мини-игру; тесты в
``tests/test_regressions.py`` держат на неё регресс.
"""
from __future__ import annotations

import random
import struct
import zlib
from pathlib import Path
from typing import Callable

BuildFn = Callable[..., None]


class Fixture:
    """Описание одного фикстурного стенда."""

    def __init__(self, name: str, build: BuildFn, doc: str = "", bugs: tuple[str, ...] = ()):
        self.name = name
        self.build = build
        self.doc = doc
        self.bugs = bugs  # известные баги, на которые есть регресс-кейс

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Fixture {self.name}>"


def ensure_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    return root


def png_stub(w: int, h: int) -> bytes:
    """Настоящий PNG с заданными размерами в IHDR.

    Пиксели ДЕТЕРМИНИРОВАНЫ (det_bytes), иначе фикстура не пересобирается
    побайтово и любой тест «фикстуры детерминированы» падает через раз.
    """
    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    raw = b"\x00" + det_bytes(w * 3, seed=f"png:{w}x{h}")
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# Unity
# ---------------------------------------------------------------------------


def det_bytes(n: int, seed: str = "") -> bytes:
    """Детерминированные «случайные» байты: фикстуры должны пересобираться побайтово."""
    import hashlib as _h
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += _h.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    return bytes(out[:n])
