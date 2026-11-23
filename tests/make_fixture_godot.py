"""Стенд Godot: PCK v2, .tscn-зависимости (включая битую)."""
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
def make_godot(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    files = {
        "res://project.binary": det_bytes(256, 'godot-bin'),
        "res://icon.png": png_stub(4, 4),
        "res://scenes/main.tscn": b'[gd_scene load_steps=2 format=3]\n[ext_resource type="Texture2D" path="res://icon.png" id="1"]\n',
        "res://scenes/menu.tscn": b'[gd_scene format=3]\n[ext_resource type="Texture2D" path="res://ui/missing_bg.png" id="1"]\n',
        "res://scripts/player.gdc": det_bytes(512, 'godot-gdc'),
        "res://audio/theme.ogg": b"OggS" + det_bytes(4096, 'theme'),
    }
    pack = root / "game.pck"
    body = b""
    table_entries = []
    offset = 0
    for name, data in files.items():
        table_entries.append((name, offset, len(data)))
        body += data
        offset += len(data)

    # соберём таблицу
    table = b""
    for name, ofs, size in table_entries:
        raw_name = name.encode() + b"\x00"
        table += struct.pack("<I", len(raw_name)) + raw_name + struct.pack("<QQ", ofs, size) + b"\x00" * 16

    header_size = 4 + 4 + 12 + 4 + 8 + 64 + 4  # magic, packver, v x3, flags, file_base, reserved, count
    data_start = header_size + len(table)
    header = (b"GDPC" + struct.pack("<I", 2)
              + struct.pack("<III", 4, 2, 1) + struct.pack("<I", 0)  # flags: offset абсолютный
              + struct.pack("<Q", 0) + b"\x00" * 64 + struct.pack("<I", len(table_entries)))
    # flags=0 => смещения относительные? В v2 смещения в таблице: если dirEncrypted=0,
    # принято хранить абсолютные — но наш сканер трактует как есть для flags&2=0.
    # Поэтому запишем абсолютные смещения:
    table = b""
    for name, ofs, size in table_entries:
        raw_name = name.encode() + b"\x00"
        table += (struct.pack("<I", len(raw_name)) + raw_name
                  + struct.pack("<QQ", data_start + ofs, size) + b"\x00" * 16)
    pack.write_bytes(header + table + body)

    (root / "project.godot").write_text(
        "config_version=5\n\n[application]\nconfig/name=\"Fixture Godot Game\"\n"
        "config/features=PackedStringArray(\"4.2\", \"GL Compatibility\")\n", "utf-8")
    (root / "ui" / "missing_dir_placeholder.txt").parent.mkdir(parents=True, exist_ok=True)
    (root / "ui" / "missing_dir_placeholder.txt").write_text("", "utf-8")


# ---------------------------------------------------------------------------
# GameMaker
# ---------------------------------------------------------------------------


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_godot(root)
    if with_bug:
        _inject_bug(root)
    return root


# Описание регресс-кейса: что ломалось и какой тест это ловит.
BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError(f"у стенда {__name__} нет регресс-кейса")
