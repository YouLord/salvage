#!/usr/bin/env python3
"""Сборка синтетического тестового стенда: 5 «игр» на разных движках.

Ничего не скачивает. Форматы повторяют реальные структуры:
  unity/    — globalgamemanagers, resources.assets со СЛОЖЕННЫМ заголовком
              (размер serialized-файла, version=17, тип-дерево, объект Texture2D),
              *.resource (сырые байты), Managed/Assembly-CSharp.dll (заглушка)
  godot/    — GDPC v2: заголовок, таблица файлов, данные; project.godot;
              .tscn со ссылками (в т.ч. битой)
  gm/       — data.win (FORM/DATA, GEN8+SPRT+TXTR+STRG), спрайт .yy
  rm_mv/    — System.json с ключом, зашифрованный .rpgmvp (фейк-заголовок + XOR)
  renpy/    — .rpa 3.0 с индексом zlib, game/script.rpyc (заглушка)
"""
from __future__ import annotations

import json
import os
import random
import struct
import zlib
from pathlib import Path

BASE = Path(__file__).resolve().parent / "fixtures"


def png_stub(w: int, h: int) -> bytes:
    """Настоящий PNG 1×1 c заданными размерами в IHDR (плюс шум для энтропии)."""
    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0)
    raw = b"\x00" + bytes(random.randrange(256) for _ in range(w * 3))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


# ---------------------------------------------------------------------------
# Unity
# ---------------------------------------------------------------------------

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
    (data / "resources.assets.resS").write_bytes(os.urandom(4096))
    (data / "globalgamemanagers").write_bytes(header + type_tree + struct.pack("<i", 1))
    (data / "sharedassets0.assets").write_bytes(header + type_tree + body)
    (data / "Managed" / "Assembly-CSharp.dll").write_bytes(b"MZ" + b"\x90" * 2048)
    (data / "Managed" / "UnityEngine.CoreModule.dll").write_bytes(b"MZ" + b"\x90" * 1024)
    (data / "StreamingAssets" / "level.map").write_bytes(os.urandom(2048))

    (root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 4096)
    (root / "UnityPlayer.dll").write_bytes(b"MZ" + b"\x00" * 8192)
    (root / "Game_Data" / "settings.json").write_text(json.dumps({
        "buildVersion": "1.0.0", "apiKey": "AKIAIOSFODNN7EXAMPLE",
        "server": "https://api.example-game.com/v1", "db": "10.0.0.15"
    }), "utf-8")


# ---------------------------------------------------------------------------
# Godot (PCK v2)
# ---------------------------------------------------------------------------

def make_godot(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    files = {
        "res://project.binary": os.urandom(256),
        "res://icon.png": png_stub(4, 4),
        "res://scenes/main.tscn": b'[gd_scene load_steps=2 format=3]\n[ext_resource type="Texture2D" path="res://icon.png" id="1"]\n',
        "res://scenes/menu.tscn": b'[gd_scene format=3]\n[ext_resource type="Texture2D" path="res://ui/missing_bg.png" id="1"]\n',
        "res://scripts/player.gdc": os.urandom(512),
        "res://audio/theme.ogg": b"OggS" + os.urandom(4096),
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

def make_gamemaker(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return tag + struct.pack("<I", len(payload)) + payload

    gen8 = b"\x00" + b"\x43" + b"\x00" * 30  # флаг + версия байткода (0x43 & 0x7f = 67? — как есть)
    gen8 = b"\x00" + b"\x11" + b"\x00" * 30  # версия байткода 17
    sprt = b"\x00" * 128
    txtr = b"\x00" * 4096 + png_stub(8, 8)
    strg = b"\x00" * 64
    body = chunk(b"GEN8", gen8) + chunk(b"SPRT", sprt) + chunk(b"TXTR", txtr) + chunk(b"STRG", strg)
    form = b"FORM" + struct.pack("<I", len(body) + 4) + b"DATA" + body
    (root / "data.win").write_bytes(form)
    (root / "sprites" / "spr_player").mkdir(parents=True, exist_ok=True)
    (root / "sprites" / "spr_player" / "spr_player.yy").write_text(json.dumps({
        "modelName": "GMSprite", "name": "spr_player", "width": 32, "height": 32,
        "frames": [{"name": "spr_player"}]}), "utf-8")
    (root / "objects" / "obj_player").mkdir(parents=True, exist_ok=True)
    (root / "objects" / "obj_player" / "obj_player.yy").write_text(json.dumps({
        "modelName": "GMObject", "name": "obj_player"}), "utf-8")


# ---------------------------------------------------------------------------
# RPG Maker MV
# ---------------------------------------------------------------------------

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
    (audio / "theme.rpgmvo").write_bytes(encrypt(b"OggS" + os.urandom(2048)))


# ---------------------------------------------------------------------------
# Ren'Py (RPA-3.0)
# ---------------------------------------------------------------------------

def make_renpy(root: Path) -> None:
    game = root / "game"
    game.mkdir(parents=True, exist_ok=True)
    (game / "script.rpyc").write_bytes(b"RENPY RPC2" + b"\x00" * 512)

    entries = {
        "images/bg room.png": png_stub(8, 8),
        "audio/theme.ogg": b"OggS" + os.urandom(1024),
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


def main() -> None:
    random.seed(42)
    BASE.mkdir(parents=True, exist_ok=True)
    make_unity(BASE / "unity")
    make_godot(BASE / "godot")
    make_gamemaker(BASE / "gm")
    make_rpgmaker_mv(BASE / "rm_mv")
    make_renpy(BASE / "renpy")
    print(f"Стенд собран: {BASE}")
    for d in sorted(BASE.iterdir()):
        n = sum(1 for _ in d.rglob("*") if _.is_file())
        print(f"  {d.name:<10} файлов: {n}")


if __name__ == "__main__":
    main()
