"""Стенд Unity: serialized-файлы, Managed, StreamingAssets, секреты."""
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
def make_unity(root: Path) -> None:
    data = root / "Game_Data"
    (data / "Managed").mkdir(parents=True, exist_ok=True)
    (data / "StreamingAssets").mkdir(parents=True, exist_ok=True)

    # serialized file (упрощённый, но со всеми узнаваемыми полями)
    header = struct.pack(">IIIII", 64, 96, 17, 46, 1 << 20)  # meta,size,ver,dataOff,endian
    type_tree = bytes(46)  # хвост-оффсеты (нули — тип-дерево «пустое»)
    # объект Texture2D: classID 28, pathID, байты
    body = struct.pack("<i", 28) + struct.pack("<q", 101) + b"UniMainTex\x00" + png_stub(8, 8)
    blob = header + type_tree + body
    (data / "resources.assets").write_bytes(blob)
    (data / "resources.assets.resS").write_bytes(det_bytes(4096, 'theme'))
    (data / "globalgamemanagers").write_bytes(header + type_tree + struct.pack("<i", 1))
    (data / "sharedassets0.assets").write_bytes(header + type_tree + body)
    (data / "Managed" / "Assembly-CSharp.dll").write_bytes(b"MZ" + b"\x90" * 2048)
    (data / "Managed" / "UnityEngine.CoreModule.dll").write_bytes(b"MZ" + b"\x90" * 1024)
    (data / "StreamingAssets" / "level.map").write_bytes(det_bytes(2048, 'audio'))

    (root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 4096)
    (root / "UnityPlayer.dll").write_bytes(b"MZ" + b"\x00" * 8192)
    (root / "Game_Data" / "settings.json").write_text(json.dumps({
        "buildVersion": "1.0.0", "apiKey": "AKIAIOSFODNN7EXAMPLE",
        "server": "https://api.example-game.com/v1", "db": "10.0.0.15"
    }), "utf-8")


# ---------------------------------------------------------------------------
# Godot (PCK v2)
# ---------------------------------------------------------------------------


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_unity(root)
    if with_bug:
        _inject_bug(root)
    return root


# Описание регресс-кейса: что ломалось и какой тест это ловит.
BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError(f"у стенда {__name__} нет регресс-кейса")
