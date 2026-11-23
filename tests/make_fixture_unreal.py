"""Стенд Unreal: .pak v3 с zlib-блоками + эталоны sha256."""
from __future__ import annotations

import json
import os
import random
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixture_base import ensure_dir, png_stub  # noqa: F401

# --------------------------------------------------------------------------
def make_unreal_pak(root: Path) -> None:
    import zlib as _zlib
    root.mkdir(parents=True, exist_ok=True)
    files = [("Content/Maps/Main.umap", b"UMAP" + bytes(range(64))),
             ("Content/Textures/T_Rock.uasset", b"UASSET" + bytes(range(128))),
             ("Content/Audio/S_Step.uasset", b"USOUND" + bytes(range(96)))]
    body = bytearray()
    records = []
    for name, data in files:
        off = len(body)
        comp = _zlib.compress(data)
        records.append((name, off, len(comp), len(data)))
        body += comp
    mount = b"../../../\x00"
    index = bytearray()
    index += struct.pack("<i", len(mount)) + mount
    index += struct.pack("<I", len(records))
    for name, off, csize, usize in records:
        nb = name.encode() + b"\x00"
        index += struct.pack("<i", len(nb)) + nb
        index += struct.pack("<QQQI", off, csize, usize, 1)
        index += b"\x00" * 20
        index += struct.pack("<I", 1)
        index += struct.pack("<QQ", off, off + csize)
        index += b"\x00"
        index += struct.pack("<I", 65536)
    index_off = len(body)
    blob = bytes(body) + bytes(index)
    blob += struct.pack("<I", 0x5A6F12E1) + struct.pack("<I", 3)
    blob += struct.pack("<QQ", index_off, len(index)) + b"\x00" * 20
    (root / "pakchunk0-WindowsNoEditor.pak").write_bytes(blob)
    import hashlib as _hashlib
    (root / "expected.json").write_text(json.dumps(
        {name: _hashlib.sha256(data).hexdigest() for name, data in files},
        ensure_ascii=False, indent=1), "utf-8")


# ---------------------------------------------------------------------------
# FMOD FSB5
# ---------------------------------------------------------------------------


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_unreal_pak(root)
    if with_bug:
        _inject_bug(root)
    return root


# Описание регресс-кейса: что ломалось и какой тест это ловит.
BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError(f"у стенда {__name__} нет регресс-кейса")
