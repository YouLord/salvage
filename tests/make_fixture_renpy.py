"""Стенд Ren'Py: RPA-3.0 + два .rpyc (RPC2 и старый zlib)."""
from __future__ import annotations

import json
import os
import pickle
import random
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixture_base import ensure_dir, png_stub, det_bytes  # noqa: F401

# --------------------------------------------------------------------------
def make_renpy(root: Path) -> None:
    game = root / "game"
    game.mkdir(parents=True, exist_ok=True)
    # старый формат (< 6.99.5): чистый zlib-поток с pickle AST
    import types as _types
    import sys as _sys
    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from salvage.core import rpyc as _rpyc
    _pkg = _types.ModuleType("renpy")
    _ast = _types.ModuleType("renpy.ast")
    _sys.modules["renpy"] = _pkg
    _sys.modules["renpy.ast"] = _ast
    try:
        _cls = type("Say", (), {"__module__": "renpy.ast", "__qualname__": "Say"})
        _ast.Say = _cls
        _obj = _cls(); _obj.who = "n"; _obj.what = "Старый формат RPYC"
        _payload = pickle.dumps([_obj], protocol=2)
    finally:
        del _sys.modules["renpy"], _sys.modules["renpy.ast"]
    (game / "script.rpyc").write_bytes(zlib.compress(_payload))

    entries = {
        "images/bg room.png": png_stub(8, 8),
        "audio/theme.ogg": b"OggS" + det_bytes(1024, 'theme'),
        "gui/button.png": png_stub(4, 4),
    }
    body = b""
    meta = []
    offset = 0
    for name, data in entries.items():
        meta.append((name, offset, len(data)))
        body += data
        offset += len(data)

    key = 0x42424242
    index_lines = []
    for name, ofs, length in meta:
        index_lines.append(f"{(ofs) ^ key:x} {(length) ^ key:x} {name}")
    index_raw = ("\n".join(index_lines) + "\n").encode()
    index_z = zlib.compress(index_raw)
    header_len = len(f"RPA-3.0 {0:08x} {key:08x}\n")  # 27 байт
    index_offset = header_len + len(body)
    header = f"RPA-3.0 {index_offset:08x} {key:08x}\n".encode()
    (game / "archive.rpa").write_bytes(header + body + index_z)


# ---------------------------------------------------------------------------
# RPG Maker XP/VX/Ace: RGSSAD + данные
# ---------------------------------------------------------------------------

# --------------------------------------------------------------------------
def make_renpy_rpyc(root: Path) -> None:
    """Дополняет renpy-стенд скомпилированным скриптом (proxy-классы, без renpy)."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from salvage.core import rpyc

    game = root / "game"
    game.mkdir(parents=True, exist_ok=True)
    # Готовим pickle с классами, сериализуемыми через sys.modules-трюк
    import types
    pkg = types.ModuleType("renpy")
    ast_mod = types.ModuleType("renpy.ast")
    sys.modules["renpy"] = pkg
    sys.modules["renpy.ast"] = ast_mod
    try:
        classes = {}
        for nm, attrs in (("Label", {"name": "start"}),
                          ("Say", {"who": "e", "what": "Добро пожаловать в фикстуру!"}),
                          ("Say", {"who": "", "what": "Это строка для аудита."}),
                          ("Screen", {"screen_name": "main_menu"}),
                          ("Menu", {"items": [("Начать", "start"), ("Выход", "quit")]})):
            cls = classes.get(nm) or type(nm, (), {"__module__": "renpy.ast", "__qualname__": nm})
            classes[nm] = cls
            setattr(ast_mod, nm, cls)
        nodes = []
        for nm, attrs in (("Label", {"name": "start"}),
                          ("Say", {"who": "e", "what": "Добро пожаловать в фикстуру!"}),
                          ("Say", {"who": "", "what": "Это строка для аудита."}),
                          ("Screen", {"screen_name": "main_menu"})):
            obj = getattr(ast_mod, nm)()
            for k, v in attrs.items():
                setattr(obj, k, v)
            nodes.append(obj)
        payload = pickle.dumps(nodes, protocol=2)
    finally:
        del sys.modules["renpy"], sys.modules["renpy.ast"]
    comp = zlib.compress(payload)
    blob = (b"RENPY RPC2" + struct.pack("<III", 1, 34, len(comp))
            + struct.pack("<III", 0, 0, 0) + comp)
    (game / "compiled.rpyc").write_bytes(blob)


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_renpy(root)
    make_renpy_rpyc(root)
    if with_bug:
        _inject_bug(root)
    return root


# Описание регресс-кейса: что ломалось и какой тест это ловит.
BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError(f"у стенда {__name__} нет регресс-кейса")
