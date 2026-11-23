"""Стенд RPG Maker XP/VX/Ace: RGSSAD v1 + RGSS3A v3 + rxdata/rvdata2 + эталоны sha256."""
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
def make_rpgmaker_xp(root: Path) -> None:
    """RGSSAD v1 (XP) и RGSS3A v3 (VX Ace) + rxdata/rvdata2."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from salvage.plugins.rpgmaker.plugin import advance_key
    from salvage.core import ruby_marshal as rm

    root.mkdir(parents=True, exist_ok=True)

    def enc_words(data: bytes, key: int) -> bytes:
        out = bytearray()
        k = key
        for i in range(0, len(data), 4):
            w = data[i:i + 4]
            out += (int.from_bytes(w.ljust(4, b"\x00"), "little") ^ k).to_bytes(4, "little")[:len(w)]
            k = (k * 7 + 3) & 0xFFFFFFFF
        return bytes(out)

    files = [
        ("Graphics/Pictures/bg.png", png_stub(16, 16)),
        ("Graphics/Characters/hero.png", png_stub(8, 8)),
        ("Audio/BGM/theme.ogg", b"OggS" + bytes(range(200))),
        ("Data/Scripts.rxdata", b"\x04\x08[\x06i\x06"),
    ]
    # --- v1 ---
    out = bytearray(b"RGSSAD\x00\x01")
    key = 0xDEADCAFE
    for name, data in files:
        nb = name.encode()
        out += struct.pack("<I", len(nb) ^ key); key = (key * 7 + 3) & 0xFFFFFFFF
        out += enc_words(nb, key); key = advance_key(key, (len(nb) + 3) // 4)
        out += struct.pack("<I", len(data) ^ key); key = (key * 7 + 3) & 0xFFFFFFFF
        out += enc_words(data, key); key = advance_key(key, (len(data) + 3) // 4)
    (root / "Game.rgssad").write_bytes(bytes(out))

    # --- v3 ---
    seed = 0x12345678
    meta_key = (seed * 9 + 3) & 0xFFFFFFFF
    kb = meta_key.to_bytes(4, "little")
    recs = [(n.encode(), d) for n, d in files[:3]]

    def assemble(offsets):
        idx = bytearray()
        for (nb, d), off in zip(recs, offsets):
            fk = 0x0BADF00D
            idx += struct.pack("<I", off ^ meta_key)
            idx += struct.pack("<I", len(d) ^ meta_key)
            idx += struct.pack("<I", fk ^ meta_key)
            idx += struct.pack("<I", len(nb) ^ meta_key)
            padded = (kb * ((len(nb) + 3) // 4))[:len(nb)]
            idx += bytes(a ^ b for a, b in zip(nb, padded))
        return bytes(idx)

    idx0 = assemble([0] * len(recs))
    offs = [8 + 4 + len(idx0)]
    for i in range(1, len(recs)):
        offs.append(offs[-1] + len(recs[i - 1][1]))
    body = bytearray(b"RGSSAD\x00\x03") + struct.pack("<I", seed) + assemble(offs)
    for nb, d in recs:
        body += enc_words(d, 0x0BADF00D)
    (root / "Game.rgss3a").write_bytes(bytes(body))

    # --- VX (.rgss2a) ---------------------------------------------------
    # Проверено по эталонным реализациям (rpgo, RPGMakerDecrypter): версии 2
    # формата НЕ существует. VX пишет «RGSSAD\x00\x01» — ту же схему, что XP,
    # только под именем Game.rgss2a. Стенд держит то, что бывает на диске:
    #   * vx.rgss2a   — magic 0x01 (как пишет сам VX);
    #   * vx_b2.rgss2a — magic 0x02 (патченные сборки): читается той же схемой.
    def _vx_archive(version_byte: int) -> bytes:
        vx_files = [
            ("Data/Actors.rvdata", b"\x04\x08[\x06i\x06"),
            ("Graphics/System/Window.png", png_stub(8, 8)),
            ("Audio/BGM/vx_theme.ogg", b"OggS" + bytes(range(64))),
        ]
        blob = bytearray(b"RGSSAD\x00" + bytes([version_byte]))
        key = 0xDEADCAFE
        for name, data in vx_files:
            nb = name.encode()
            blob += struct.pack("<I", len(nb) ^ key); key = (key * 7 + 3) & 0xFFFFFFFF
            blob += enc_words(nb, key); key = advance_key(key, (len(nb) + 3) // 4)
            blob += struct.pack("<I", len(data) ^ key); key = (key * 7 + 3) & 0xFFFFFFFF
            blob += enc_words(data, key); key = advance_key(key, (len(data) + 3) // 4)
        return bytes(blob)

    vx_files = [
        ("Data/Actors.rvdata", b"\x04\x08[\x06i\x06"),
        ("Graphics/System/Window.png", png_stub(8, 8)),
        ("Audio/BGM/vx_theme.ogg", b"OggS" + bytes(range(64))),
    ]
    (root / "Game.rgss2a").write_bytes(_vx_archive(1))       # как у настоящего VX
    (root / "vx_b2.rgss2a").write_bytes(_vx_archive(2))      # патченный байт версии
    (root / "vx_b3.rgss2a").write_bytes(_vx_archive(3))      # чужой байт: должен падать
    import hashlib as _h
    (root / "expected_rgss_v2.json").write_text(json.dumps(
        {name: _h.sha256(data).hexdigest() for name, data in vx_files}, indent=1), "utf-8")

    # --- данные XP/VX/Ace ---
    data_dir = root / "Data"
    data_dir.mkdir(exist_ok=True)
    actors = [None, {"__class__": "RPG::Actor",
                     "ivars": {"id": 1, "name": "Герой", "class_id": 1,
                               "parameters": [[1, 2, 3], [4, 5, 6]]}},
              {"__class__": "RPG::Actor",
               "ivars": {"id": 2, "name": "Маг", "class_id": 2}}]
    (data_dir / "Actors.rxdata").write_bytes(rm.json_to_marshal(actors))
    system = {"__class__": "RPG::System", "ivars": {"title": "Фикстура XP", "version_id": 1}}
    (data_dir / "System.rvdata2").write_bytes(rm.json_to_marshal(system))
    mapinfo = [None, {"id": 1, "name": "Деревня", "order": 1}]
    (data_dir / "MapInfos.rvdata2").write_bytes(rm.json_to_marshal(mapinfo))

    # эталоны для байт-в-байт проверки расшифровки
    import hashlib as _hashlib
    (root / "expected_rgss.json").write_text(json.dumps(
        {name: _hashlib.sha256(data).hexdigest() for name, data in files},
        ensure_ascii=False, indent=1), "utf-8")


# ---------------------------------------------------------------------------
# Unreal .pak (v3)
# ---------------------------------------------------------------------------


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_rpgmaker_xp(root)
    if with_bug:
        _inject_bug(root)
    return root


# Регресс-кейс: без System.json (и без ключа) extract делал early-return и
# сообщал «извлечено 0», хотя RGSS-архив не шифрован. Минимальная игра:
# только Game.rgssad.
BUG_CASE = {
    "id": "rm-early-return-without-key",
    "было": "extract без ключа MV/MZ возвращал 0 файлов и не трогал RGSS",
    "стало": "RGSS-архив извлекается всегда, ключ нужен только MV/MZ",
    "тест": "tests/test_regressions.py::test_regression_rm_without_system_json",
}


def _inject_bug(root: Path) -> None:
    import shutil as _shutil
    for child in list(root.iterdir()):
        if child.name not in ("Game.rgssad", "expected_rgss.json"):
            _shutil.rmtree(child) if child.is_dir() else child.unlink()
