"""Стенд FMOD: FSB5-банк с 3 PCM16-сэмплами."""
from __future__ import annotations

import json
import os
import random
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixture_base import ensure_dir, png_stub, det_bytes  # noqa: F401

# --------------------------------------------------------------------------
def make_fmod(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    # Реальная раскладка FSB5 v1 (см. vgmstream fsb5.c):
    #   база 0x3C, затем заголовки сэмплов (64-битное поле + цепочки чанков),
    #   таблица имён (uint32-офсеты), данные. Смещение данных — в единицах
    #   по 32 байта (биты 8..33), число сэмплов — биты 34..63.
    def header(off_units: int, samples_n: int, freq: int = 8, channels_code: int = 0) -> bytes:
        mode = (channels_code << 5) | (freq << 1)
        mode |= off_units << 7
        mode |= samples_n << 34
        return struct.pack("<Q", mode)

    samples_n = 2000
    payloads = [det_bytes(96, 's1'), det_bytes(128, 's2'), det_bytes(96, 's3')]
    # выравниваем каждый сэмпл на 32 байта — как это делает FMOD
    offs, cursor = [], 0
    for pl in payloads:
        offs.append(cursor // 32)
        cursor += ((len(pl) + 31) // 32) * 32
    data = bytearray()
    for pl in payloads:
        data += pl
        data += b"\x00" * (((len(pl) + 31) // 32) * 32 - len(pl))
    shdr = b"".join(header(o, samples_n) for o in offs)
    # таблица имён: офсеты от начала таблицы, строки с NUL
    raw_names = [b"step_01", b"impact_02", b"ui_click"]
    table_size = 4 * len(raw_names)
    name_table = bytearray(struct.pack("<" + "I" * len(raw_names),
                                       *[table_size + sum(len(n) + 1 for n in raw_names[:i])
                                         for i in range(len(raw_names))]))
    for n in raw_names:
        name_table += n + b"\x00"
    hdr = (b"FSB5" + struct.pack("<iiiiii", 1, len(payloads), len(shdr),
                                 len(name_table), len(data), 2)
           + b"\x00" * 8 + b"\x00" * 16 + b"\x00" * 8)
    assert len(hdr) == 0x3C, len(hdr)
    (root / "SFX.bank").write_bytes(hdr + shdr + bytes(name_table) + bytes(data))


# ---------------------------------------------------------------------------
# Ren'Py: RPYC2 с AST
# ---------------------------------------------------------------------------


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_fmod(root)
    if with_bug:
        _inject_bug(root)
    return root


# Описание регресс-кейса: что ломалось и какой тест это ловит.
BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError(f"у стенда {__name__} нет регресс-кейса")
