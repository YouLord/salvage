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
    """UE .pak v3: layout как у настоящих паков.

    Запись = [заголовок записи][данные], offset записи указывает на её
    заголовок, блоки (start,end) — абсолютные смещения сжатых данных.
    """
    import hashlib
    import zlib as _zlib

    root.mkdir(parents=True, exist_ok=True)
    files = [("Content/Maps/Main.umap", b"UMAP" + bytes(range(64))),
             ("Content/Textures/T_Rock.uasset", b"UASSET" + bytes(range(128))),
             ("Content/Audio/S_Step.uasset", b"USOUND" + bytes(range(96)))]
    # размер заголовка записи v3 с одним блоком:
    # offset,size,unc,method (28) + sha1 (20) + blocks count (4) + блок (16)
    # + encrypted (1) + block_size (4) = 73
    HEADER = 73
    mount = b"../../../\x00"

    # двухпроходно: сначала раскладка (offset записи), затем байты
    layout = []
    cursor = 0
    for name, data in files:
        comp = _zlib.compress(data)
        header_off = cursor
        data_off = header_off + HEADER
        layout.append((name, data, comp, header_off, data_off))
        cursor = data_off + len(comp)

    blob = bytearray()
    for name, data, comp, header_off, data_off in layout:
        hdr = struct.pack("<QQQI", header_off, len(comp), len(data), 1)
        hdr += b"\x00" * 20                                  # sha1 (не проверяем)
        hdr += struct.pack("<I", 1)                           # blocks count
        hdr += struct.pack("<QQ", data_off, data_off + len(comp))
        hdr += b"\x00"                                       # encrypted
        hdr += struct.pack("<I", 65536)                       # block size
        assert len(hdr) == HEADER, len(hdr)
        assert len(blob) == header_off
        blob += hdr
        assert len(blob) == data_off
        blob += comp

    index = bytearray()
    index += struct.pack("<i", len(mount)) + mount
    index += struct.pack("<I", len(layout))
    for name, data, comp, header_off, data_off in layout:
        nb = name.encode() + b"\x00"
        index += struct.pack("<i", len(nb)) + nb
        index += struct.pack("<QQQI", header_off, len(comp), len(data), 1)
        index += b"\x00" * 20
        index += struct.pack("<I", 1)
        index += struct.pack("<QQ", data_off, data_off + len(comp))
        index += b"\x00"
        index += struct.pack("<I", 65536)
    index_off = len(blob)
    blob += index
    blob += struct.pack("<I", 0x5A6F12E1) + struct.pack("<I", 3)
    blob += struct.pack("<QQ", index_off, len(index)) + b"\x00" * 20
    (root / "pakchunk0-WindowsNoEditor.pak").write_bytes(bytes(blob))
    (root / "expected.json").write_text(json.dumps(
        {name: hashlib.sha256(data).hexdigest() for name, data in files},
        ensure_ascii=False, indent=1), "utf-8")



def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_unreal_pak(root)
    if with_bug:
        _inject_bug(root)
    return root


BUG_CASE = {
    "id": "ue-offset-points-to-record-header",
    "было": "данные читались с offset записи, а не с offset+header_size",
    "стало": "сначала заголовок записи, затем данные; блоки абсолютные",
    "тест": "tests/test_regressions.py::test_regression_ue_offset_semantics",
}


def _inject_bug(root: Path) -> None:
    """Мини-игра: один сжатый файл, где offset записи != началу данных."""
    for child in list(root.iterdir()):
        if child.name != "pakchunk0-WindowsNoEditor.pak":
            child.unlink()
