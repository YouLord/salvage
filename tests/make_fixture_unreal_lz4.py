"""Стенд Unreal .pak v8 с LZ4-блоками (и одним zlib для контроля).

v8: footer 193 байта, в нём 4 имени методов сжатия по 32 байта. Индекс —
плоский список v1–v9. Запись v8: offset, size, unc, method, sha1, блоки,
encrypted-байт, block_size.

LZ4-блок в pak хранится как raw LZ4 (без store_size): распаковка требует
ожидаемого размера, который берётся из block_size записи.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixture_base import ensure_dir


def _lz4(data: bytes) -> bytes | None:
    try:
        import lz4.block
        return lz4.block.compress(data, store_size=False)
    except Exception:
        return None


def build(root: Path, *, with_bug: bool = False) -> Path:
    """UE .pak v8: LZ4-блоки + zlib-контроль.

    Как в настоящих паках: offset записи → её заголовок, затем данные;
    блоки (start,end) — абсолютные смещения. При block_count == 1 данные
    лежат подряд без 4-байтного префикса размера.
    """
    ensure_dir(root)
    files = {
        "Content/Meshes/SM_Crate.uasset": (bytes(range(256)) * 40),
        "Content/Textures/T_Grass.uasset": (b"TEXTURE" + bytes(range(200)) * 20),
        "Content/Audio/S_Hit.uasset": (b"SOUND" + bytes(range(128)) * 10),
    }
    method_lz4 = 2
    method_zlib = 1
    lz4_missing = False
    # v8 header: offset,size,unc,method (28) + sha1 (20) + count (4) + block (16)
    #            + encrypted (1) + block_size (4) + unknown (1) = 74
    HEADER = 74
    plan = []
    cursor = 0
    for i, (name, data) in enumerate(files.items()):
        if i < 2:
            comp = _lz4(data)
            if comp is None:
                lz4_missing = True
                comp, method = zlib.compress(data), method_zlib
            else:
                method = method_lz4
        else:
            comp, method = zlib.compress(data), method_zlib
        header_off = cursor
        data_off = header_off + HEADER
        plan.append((name, data, comp, method, header_off, data_off))
        cursor = data_off + len(comp)

    blob = bytearray()
    for name, data, comp, method, header_off, data_off in plan:
        hdr = struct.pack("<QQQI", header_off, len(comp), len(data), method)
        hdr += b"\x00" * 20
        hdr += struct.pack("<I", 1)
        hdr += struct.pack("<QQ", data_off, data_off + len(comp))
        hdr += b"\x00"
        hdr += struct.pack("<I", len(data))
        hdr += b"\x00"
        assert len(hdr) == HEADER, len(hdr)
        blob += hdr
        blob += comp

    index = bytearray()
    mount = b"../../../\x00"
    index += struct.pack("<i", len(mount)) + mount
    index += struct.pack("<I", len(plan))
    for name, data, comp, method, header_off, data_off in plan:
        nb = name.encode() + b"\x00"
        index += struct.pack("<i", len(nb)) + nb
        index += struct.pack("<QQQI", header_off, len(comp), len(data), method)
        index += b"\x00" * 20
        index += struct.pack("<I", 1)
        index += struct.pack("<QQ", data_off, data_off + len(comp))
        index += b"\x00"
        index += struct.pack("<I", len(data))
        index += b"\x00"
    index_off = len(blob)
    blob += index
    # footer v8: 16 guid + 1 encrypted + magic + version + index off/size + sha1 + 4×32
    blob += b"\x00" * 16
    blob += b"\x00"
    blob += struct.pack("<II", 0x5A6F12E1, 8)
    blob += struct.pack("<QQ", index_off, len(index))
    blob += b"\x00" * 20
    for name in (b"None", b"Zlib", b"LZ4", b"Oodle"):
        blob += name.ljust(32, b"\x00")
    (root / "pakchunk0-WindowsNoEditor.pak").write_bytes(bytes(blob))
    meta = {
        "lz4_available": not lz4_missing,
        "files": {name: {"size": len(data),
                         "sha256": hashlib.sha256(data).hexdigest(),
                         "method": ("lz4" if method == method_lz4 else "zlib")}
                  for name, data, comp, method, *_ in plan},
    }
    (root / "expected_lz4.json").write_text(json.dumps(meta, indent=1), "utf-8")
    return root


BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError
