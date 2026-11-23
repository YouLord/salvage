"""Стенд GameMaker: data.win (SPRT/TPAG/TXTR/SOND/AUDO/STRG) + audiogroup1.dat + .yy."""
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


def build(root: Path, *, with_bug: bool = False) -> Path:
    """Собрать стенд. with_bug=True добавляет регресс-кейс BUG_CASE."""
    random.seed(42)
    ensure_dir(root)
    make_gamemaker(root)
    if with_bug:
        _inject_bug(root)
    return root


# Регресс-кейс: audiogroup1.dat имеет магию gamemaker_win и до фикса
# индексировался как «данные», а не как внешняя аудиогруппа → sn_music.ogg
# не извлекался. Минимальная игра: только data.win + audiogroup1.dat.
BUG_CASE = {
    "id": "gm-audiogroup-as-datas",
    "было": "audiogroup1.dat считался data-файлом, звук из него не извлекался",
    "стало": "внешняя группа разбирается по имени *.dat, audio/sn_music.ogg на месте",
    "тест": "tests/test_regressions.py::test_regression_gm_external_audiogroup",
}


def _inject_bug(root: Path) -> None:
    import shutil as _shutil
    keep = {"data.win", "audiogroup1.dat"}
    for child in root.iterdir():
        if child.name not in keep:
            _shutil.rmtree(child) if child.is_dir() else child.unlink()
