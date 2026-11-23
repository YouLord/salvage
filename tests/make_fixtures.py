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
import pickle
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
    """data.win с реальными чанками + внешняя аудиогруппа audiogroup1.dat."""
    import bz2
    import zlib as _zlib
    root.mkdir(parents=True, exist_ok=True)

    # --- строки ---
    strings = ["spr_player", "obj_player", "rm_room", "scr_move", "sh_pass",
               "sn_click", "sn_music", "Font1"]
    str_payload = bytearray()
    count = len(strings)
    offsets = []
    pos = 4 + 4 * count
    for st in strings:
        offsets.append(pos)  # относительные смещения от начала payload; при сборке станут абсолютными
        raw = st.encode() + b"\x00"
        str_payload += raw
        pos += len(raw)
    # таблица офсетов заполняется абсолютными адресами при сборке (см. build_full)

    def str_ptr(i: int) -> int:
        # абсолютный адрес строки будет известен после сборки — используем placeholder,
        # затем перезапишем по смещениям (см. _fix_strings ниже).

        return offsets[i]

    # --- текстуры: 3 страницы: PNG, QOI, BZ2(QOI) ---
    def png_bytes(w, h, seed=0):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from salvage.core import imaging
        flat = bytearray()
        for y in range(h):
            for x in range(w):
                flat += bytes(((x * 7 + y * 11 + seed) & 0xFF,
                               (x * 3) & 0xFF, (y * 5) & 0xFF, 255))
        return imaging.encode_png_rgba(bytes(flat), w, h), bytes(flat), w, h

    png1, rgba1, w1, h1 = png_bytes(32, 32, 1)
    png2, rgba2, w2, h2 = png_bytes(16, 16, 2)
    from salvage.core import imaging
    qoi2 = imaging.encode_qoi(rgba2, w2, h2)
    # третья страница: BZ2 от QOI
    qoi3 = imaging.encode_qoi(rgba1, w1, h1)
    bz2_qoi = bz2.compress(qoi3)
    tex_payloads = [png1, qoi2, bz2_qoi]

    # --- TPAG: 4 ректа (по 2 на стрелки) ---
    tpag_entries = [
        (0, 0, 16, 16, 0), (16, 0, 16, 16, 0),   # в странице 0
        (0, 0, 16, 16, 1),                        # в странице 1
        (0, 0, 16, 16, 2),                        # в странице 2 (bz2+qoi)
    ]

    # --- сборка чанков с абсолютными смещениями ---
    # Формат GameMaker: список офсетов (абсолютные адреса записей),
    # записи идут в файле ПОСЛЕ чанка. Соберём двухпроходно.
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return tag + struct.pack("<I", len(payload)) + payload

    # предварительная сборка для вычисления базы
    def build(data_start_guess=0):
        pass

    # 1) GEN8
    gen8 = b"\x00\x11" + b"\x00" * 30
    # 2) SPRT: 1 спрайт с 2 кадрами (tpag 0 и 1)
    # раскладка (GMS2-подобная): [name][w][h][ml][mr][mb][mt][u0..u2][bbox][sepmask][ox][oy][texcount][tpag...]
    sprt_rec = struct.pack("<I", 0)                                  # name
    sprt_rec += struct.pack("<ii", 32, 32)                           # w, h
    sprt_rec += struct.pack("<4i", 0, 0, 0, 0)                       # margins
    sprt_rec += struct.pack("<3I", 0, 0, 0)                          # unknown[3]
    sprt_rec += struct.pack("<II", 0, 0)                             # bbox mode, sep masks
    sprt_rec += struct.pack("<ii", 16, 16)                           # origin x/y
    sprt_rec += struct.pack("<i", 2) + struct.pack("<ii", 0, 1)      # texcount, tpag ids
    # 3) TPAG
    # запись ровно 24 байта: 11×u16 (22) + tex u32 на +20 (перекрытие как в реальном
    # формате: tex занимает смещения 20..23)
    tpag_recs = b""
    for (x, y, w, h, tex) in tpag_entries:
        rec = bytearray(24)
        struct.pack_into("<8H", rec, 0, x, y, w, h, 0, 0, 0, 0)
        struct.pack_into("<H", rec, 16, w)
        struct.pack_into("<H", rec, 18, h)
        struct.pack_into("<I", rec, 20, tex)
        tpag_recs += bytes(rec)
    # 4) TXTR: 3 страницы; FileInfo[0] = (unknown, blob_off); blob = u32 len + data
    # 5) SOND: 2 звука: один в группе 0 (встроенный), второй в группе 1 (внешняя)
    sond_recs = []
    for i, (name_idx, group, aid) in enumerate([(5, 0, 0), (6, 1, 0)]):
        rec = struct.pack("<I", 0)  # имя
        rec += struct.pack("<I", 0)  # flags
        rec += struct.pack("<I", 0)  # type
        rec += struct.pack("<I", 0)  # file
        rec += struct.pack("<I", 0)  # unknown
        rec += struct.pack("<f", 1.0) + struct.pack("<f", 1.0)  # volume, pitch
        rec += struct.pack("<i", group) + struct.pack("<i", aid)
        sond_recs.append((rec, name_idx))
    # 6) AUDO: 1 встроенный звук (Ogg)
    ogg = b"OggS" + bytes(range(256)) * 2
    audo_payloads = [ogg]
    # 7) OBJT/ROOM/SCPT/SHDR: списки с именами (минимальные записи = 4 байта имени)
    named_chunks = {b"OBJT": [1], b"ROOM": [2], b"SCPT": [3], b"SHDR": [4], b"FONT": [7]}

    # --- двухпроходная сборка ---
    # Раскладка: [FORM hdr][GEN8][SPRT][TPAG][TXTR][SOND][AUDO][STRG][named...]
    # Записи чанков идут СРАЗУ после заголовка чанка (как в реальном формате),
    # поэтому абсолютные адреса вычисляем послойно.
    def assemble():
        chunks = []
        # порядок важен: строки понадобятся всем
        chunks.append(chunk(b"GEN8", gen8))
        return chunks

    # Собираем вручную с фиксированным layout:
    form_hdr = 12
    # Заголовки чанков по 8 байт; payload'ы:
    def chunk_hdr_len(tag_len=4):
        return 8

    # вычислим размеры payload'ов
    def sprt_payload():
        # list: count + offsets + records
        return struct.pack("<I", 1) + struct.pack("<I", 0) + b"\x00" * 4  # offsets + placeholder

    # Из-за сложности относительных ссылок соберём «как настоящий GameMaker»:
    #   payload = count, offsets[](абс. адреса записей), затем записи
    # Адреса посчитаем, зная начала всех чанков (сдвиг фиксируем после сборки).

    # --- 1) предварительные размеры записей ---
    sprt_rec_len = len(sprt_rec)
    tpag_rec_len = 24
    sond_rec_len = len(sond_recs[0][0])
    # названия: у нас «указатели» строк = смещения внутри STRG; реальные сборки
    # хранят абсолютные адреса. Мы используем абсолютные — перезапишем ниже.

    def build_full(str_abs_base):
        # абсолютный адрес каждой строки в файле
        def sptr(i):
            return str_abs_base + offsets[i]

        parts = []
        # GEN8
        parts.append((b"GEN8", gen8))
        # SPRT
        sprt_records = bytearray(sprt_rec)
        struct.pack_into("<I", sprt_records, 0, sptr(0))
        sprt_pl = struct.pack("<I", 1) + struct.pack("<I", 0) + bytes(sprt_records)
        parts.append((b"SPRT", sprt_pl))
        # TPAG
        tpag_pl = struct.pack("<I", len(tpag_entries)) + b"\x00" * (4 * len(tpag_entries)) + tpag_recs
        parts.append((b"TPAG", tpag_pl))
        # TXTR
        tex_blobs = b""
        blob_offsets = []
        for data in tex_payloads:
            blob_offsets.append(len(tex_blobs))
            tex_blobs += struct.pack("<I", len(data)) + data
        txtr_pl = struct.pack("<I", len(tex_payloads))
        txtr_pl += b"\x00" * (4 * len(tex_payloads))       # fileinfo offsets
        for bo in blob_offsets:
            txtr_pl += struct.pack("<II", 1, bo)             # FileInfo: unknown=1, blob rel. offset
        txtr_pl += tex_blobs
        parts.append((b"TXTR", txtr_pl))
        # SOND
        sond_payload_recs = bytearray()
        for rec, name_idx in sond_recs:
            r = bytearray(rec)
            struct.pack_into("<I", r, 0, sptr(name_idx))
            sond_payload_recs += r
        sond_pl = struct.pack("<I", len(sond_recs)) + b"\x00" * (4 * len(sond_recs)) + bytes(sond_payload_recs)
        parts.append((b"SOND", sond_pl))
        # AUDO
        audo_pl = struct.pack("<I", len(audo_payloads)) + b"\x00" * (4 * len(audo_payloads))
        for data in audo_payloads:
            audo_pl += struct.pack("<I", len(data)) + data
        parts.append((b"AUDO", audo_pl))
        # STRG: count, offsets[](абс. адреса строк), затем строки
        str_lines = b"".join(st.encode() + b"\x00" for st in strings)
        str_payload_start = 4 + 4 * count
        str_offsets_abs = []
        rel = str_payload_start
        for st in strings:
            str_offsets_abs.append(str_abs_base + rel)
            rel += len(st.encode()) + 1
        str_chunk = (struct.pack("<I", count)
                     + b"".join(struct.pack("<I", o) for o in str_offsets_abs)
                     + str_lines)
        parts.append((b"STRG", str_chunk))
        # named
        for tag, idxs in named_chunks.items():
            pl = struct.pack("<I", len(idxs)) + b"".join(struct.pack("<I", 0) for _ in idxs)
            recs = b"".join(struct.pack("<I", sptr(i)) for i in idxs)
            parts.append((tag, pl + recs))
        return parts

    # двухпроходно: сначала соберём с base=0, посчитаем реальные адреса STRG,
    # затем пересоберём
    def full_build(parts):
        body = b""
        positions = {}
        for tag, pl in parts:
            positions[tag] = form_hdr + len(body) + 8  # payload start
            body += chunk(tag, pl)
        return b"FORM" + struct.pack("<I", len(body) + 4) + b"DATA" + body, positions

    parts0 = build_full(0)
    blob0, positions0 = full_build(parts0)
    str_abs = positions0[b"STRG"]
    parts = build_full(str_abs)
    blob, positions = full_build(parts)

    # --- исправим абсолютные ссылки внутри чанков, которые ссылались на 0 ---
    # SPRT: offsets[0] должен указывать на запись sprite
    def fix_list_offsets(blob: bytes, tag: bytes, count: int, record_off_delta: int):
        pos = positions[tag]
        # payload = count, offsets[count], records...
        rec_start = pos + 4 + 4 * count
        out = bytearray(blob)
        for i in range(count):
            struct.pack_into("<I", out, pos + 4 + 4 * i, rec_start + i * record_off_delta)
        return bytes(out)

    blob = fix_list_offsets(blob, b"SPRT", 1, sprt_rec_len)
    blob = fix_list_offsets(blob, b"TPAG", len(tpag_entries), tpag_rec_len)
    blob = fix_list_offsets(blob, b"SOND", len(sond_recs), sond_rec_len)
    for tag, idxs in named_chunks.items():
        blob = fix_list_offsets(blob, tag, 1, 4)

    # TXTR: fileinfo offsets = payload_start + 4 + 4*N + i*(8) относительно blob?
    # В GameMaker FileInfo[i].offset абсолютный. Перезапишем:
    out = bytearray(blob)
    txtr_pos = positions[b"TXTR"]
    n = len(tex_payloads)
    fi_start = txtr_pos + 4 + 4 * n
    # blobs начинаются после FileInfo-массива (у нас есть уже дубли смещений)
    blob_start = fi_start + 8 * n
    running = blob_start
    for i in range(n):
        struct.pack_into("<I", out, txtr_pos + 4 + 4 * i, fi_start + 8 * i)  # FileInfo адрес
        struct.pack_into("<II", out, fi_start + 8 * i, 1, running)          # unknown, blob-адрес
        running += 4 + len(tex_payloads[i])
    # AUDO: offsets на записи (u32 длина + данные)
    audo_pos = positions[b"AUDO"]
    rec = audo_pos + 4 + 4 * len(audo_payloads)
    running = rec
    for i, data in enumerate(audo_payloads):
        struct.pack_into("<I", out, audo_pos + 4 + 4 * i, running)
        running += 4 + len(data)
    (root / "data.win").write_bytes(bytes(out))

    # --- внешняя аудиогруппа 1 (отдельный FORM/DATA с AUDO) ---
    ext_audio = b"OggS" + bytes(range(128))
    audo_body = struct.pack("<I", 1) + struct.pack("<I", 0) + struct.pack("<I", len(ext_audio)) + ext_audio
    # абсолютный адрес записи: FORM(8) + DATA(4) + chunk hdr(8) + count(4) + offset[1](4)
    rec_abs = 8 + 4 + 8 + 4 + 4
    audo_body = struct.pack("<I", 1) + struct.pack("<I", rec_abs) + struct.pack("<I", len(ext_audio)) + ext_audio
    grp = chunk(b"AUDO", audo_body)
    group = b"FORM" + struct.pack("<I", len(grp) + 4) + b"DATA" + grp
    (root / "audiogroup1.dat").write_bytes(group)

    # --- проект .yy ---
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


# ---------------------------------------------------------------------------
# RPG Maker XP/VX/Ace: RGSSAD + данные
# ---------------------------------------------------------------------------

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

def make_fmod(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)

    def header(off_units, samples_n, freq=8, two=False):
        word = (off_units << 6) | ((1 if two else 0) << 5) | (freq << 1)
        return struct.pack("<I", word) + struct.pack("<I", samples_n)

    samples_n = 2000
    shdr = header(0, samples_n) + header(7, samples_n) + header(14, samples_n)
    data = os.urandom(100) + os.urandom(120) + os.urandom(90)
    names = b"step_01\x00impact_02\x00ui_click\x00"
    hdr = (b"FSB5" + struct.pack("<iiiiii", 0, 3, len(shdr), len(names), len(data), 2)
           + b"\x00" * 8 + b"\x00" * 16 + b"\x00" * 8)
    (root / "SFX.bank").write_bytes(hdr + shdr + names + data)


# ---------------------------------------------------------------------------
# Ren'Py: RPYC2 с AST
# ---------------------------------------------------------------------------

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


def main() -> None:
    random.seed(42)
    BASE.mkdir(parents=True, exist_ok=True)
    make_unity(BASE / "unity")
    make_godot(BASE / "godot")
    make_gamemaker(BASE / "gm")
    make_rpgmaker_mv(BASE / "rm_mv")
    make_rpgmaker_xp(BASE / "rm_xp")
    make_renpy(BASE / "renpy")
    make_renpy_rpyc(BASE / "renpy")
    make_unreal_pak(BASE / "ue")
    make_fmod(BASE / "fmod")
    print(f"Стенд собран: {BASE}")
    for d in sorted(BASE.iterdir()):
        n = sum(1 for _ in d.rglob("*") if _.is_file())
        print(f"  {d.name:<10} файлов: {n}")


if __name__ == "__main__":
    main()
