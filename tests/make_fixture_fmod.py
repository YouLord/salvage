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

    def header(off_units, samples_n, freq=8, two=False):
        word = (off_units << 6) | ((1 if two else 0) << 5) | (freq << 1)
        return struct.pack("<I", word) + struct.pack("<I", samples_n)

    samples_n = 2000
    shdr = header(0, samples_n) + header(7, samples_n) + header(14, samples_n)
    data = det_bytes(100, 's1') + det_bytes(120, 's2') + det_bytes(90, 's3')
    names = b"step_01\x00impact_02\x00ui_click\x00"
    hdr = (b"FSB5" + struct.pack("<iiiiii", 0, 3, len(shdr), len(names), len(data), 2)
           + b"\x00" * 8 + b"\x00" * 16 + b"\x00" * 8)
    (root / "SFX.bank").write_bytes(hdr + shdr + names + data)


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
