"""Стенд RPG Maker MV: System.json с ключом, зашифрованные ассеты."""
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
def make_rpgmaker_mv(root: Path) -> None:
    data = root / "www" / "data"
    img = root / "www" / "img" / "pictures"
    audio = root / "www" / "audio" / "bgm"
    js = root / "www" / "js"
    for d in (data, img, audio, js):
        d.mkdir(parents=True, exist_ok=True)

    key = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
    (data / "System.json").write_text(json.dumps({
        "gameTitle": "Fixture RM Game", "versionId": 800004,
        "locale": "en_US", "encryptionKey": key}), "utf-8")
    (data / "MapInfos.json").write_text(json.dumps([{"id": 1, "name": "Town"}]), "utf-8")
    (data / "Map001.json").write_text(json.dumps(
        [{"id": 1, "events": [{"id": 2}, {"id": 3}]}]), "utf-8")
    for name in ("rpg_core.js", "rpg_managers.js", "rpg_objects.js"):
        (js / name).write_text("// rpg maker core stub\n", "utf-8")

    key_bytes = bytes.fromhex(key)

    def encrypt(payload: bytes) -> bytes:
        # реальный формат: 16-байтный фейк-заголовок + данные, у которых
        # первые 16 байт заксорены ключом (без дублирования)
        head = bytearray(payload[:16].ljust(16, b"\x00"))
        for i in range(16):
            head[i] ^= key_bytes[i]
        return b"RPGMV" + b"\x00" * 11 + bytes(head) + payload[16:]

    (img / "title.rpgmvp").write_bytes(encrypt(png_stub(16, 16)))
    (img / "face.rpgmvp").write_bytes(encrypt(png_stub(8, 8)))
    (audio / "theme.rpgmvo").write_bytes(encrypt(b"OggS" + det_bytes(2048, 'audio')))


# ---------------------------------------------------------------------------
# Ren'Py (RPA-3.0)
# ---------------------------------------------------------------------------


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_rpgmaker_mv(root)
    if with_bug:
        _inject_bug(root)
    return root


# Описание регресс-кейса: что ломалось и какой тест это ловит.
BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError(f"у стенда {__name__} нет регресс-кейса")
