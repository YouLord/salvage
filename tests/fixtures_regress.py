"""Сборщики регресс-фикстур: по одной маленькой «больной» игре на баг.

Каждый ``build_*`` пишет файлы в переданный каталог и возвращает Path.
Рядом кладётся ``expected.json`` — что именно должно получиться, если баг
действительно исправлен. Тесты (``tests/test_regress.py``) не доверяют себе:
они сверяют и байты (sha256), и семантику (имена/офсеты/флаги).
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

import fixtures_lib as lib

# ---------------------------------------------------------------------------
# GameMaker: STRG с абсолютными адресами
# ---------------------------------------------------------------------------

BUG_GM_ABS_STRINGS = {
    "id": "gm-strg-absolute-offsets",
    "было": "STRG-офсеты считались относительными к payload, все имена строк пустыми",
    "стало": "пробуются все базы (abs, payload, header); имена OBJT/ROOM на месте",
    "тест": "tests/test_regress.py::TestGameMaker::test_strg_absolute_offsets",
}


def build_gm_strg_abs(root: Path) -> Path:
    """data.win, где STRG хранит АБСОЛЮТНЫЕ адреса строк (как в старых сборках).

    Ловушка: если читать офсет как смещение от payload, получаются мусорные
    строки (или пустые), и все имена ресурсов теряются.
    """
    root = lib.ensure_dir(root)
    strings = ["obj_player", "rm_start", "snd_music"]
    # Собираем вручную, зная итоговую позицию STRG-payload в файле:
    # FORM(4)+len(4)+DATA(4) + остальные чанки + STRG hdr(4)+len(4)
    other = [(b"GEN8", b"\x00" * 16)]
    strg_hdr = 8  # tag+len
    base = 4 + 4 + 4 + sum(8 + len(p) for _, p in other) + strg_hdr
    strg_payload = lib.gm_strg_with_base(strings, base=base, mode="abs")
    data = lib.gm_container(other + [(b"STRG", strg_payload)])
    path = lib.write(root / "data.win", data)
    lib.write_expected(root, "expected.json", {
        "strings": strings,
        "strg_payload_offset": base,
        "size": len(data),
        "sha256": lib.hashlib.sha256(data).hexdigest(),
    })
    return path


# ---------------------------------------------------------------------------
# GameMaker: TPAG-записи по 24 байта
# ---------------------------------------------------------------------------

BUG_GM_TPAG = {
    "id": "gm-tpag-24-byte-record",
    "было": "TPAG читался 22/28-байтовой записью → съезжали x/y/w/h и номер страницы",
    "стало": "запись 24 Б: 10×u16 + u32 tex; ректы совпадают с ожидаемыми",
    "тест": "tests/test_regress.py::TestGameMaker::test_tpag_record_layout",
}


def build_gm_tpag(root: Path) -> Path:
    root = lib.ensure_dir(root)
    rects = [(0, 0, 32, 32, 0), (32, 0, 16, 16, 0), (0, 32, 8, 8, 1)]
    # адреса в TPAG — АБСОЛЮТНЫЕ позиции в файле (эталон: UndertaleModTool).
    # payload начинается с 4+4+4 (FORM+len+DATA) + 4+4 (tag+len) = 20.
    payload_at = 20
    first_entry = payload_at + 4 + 4 * len(rects)
    tpag_payload = (struct.pack("<I", len(rects))
                    + b"".join(struct.pack("<I", first_entry + 24 * i)
                               for i in range(len(rects)))
                    + lib.gm_tpag(rects))
    # хвост-«наполнитель»: порог парсера требует места после записи,
    # иначе последний рект (по 24 Б) отбрасывается как выходящий за файл
    data = lib.gm_container([(b"TPAG", tpag_payload), (b"GEN8", b"\x00" * 64)])
    path = lib.write(root / "data.win", data)
    lib.write_expected(root, "expected.json", {
        "rects": [{"x": x, "y": y, "w": w, "h": h, "tex": t}
                  for x, y, w, h, t in rects],
        "sha256": lib.hashlib.sha256(data).hexdigest(),
    })
    return path


# ---------------------------------------------------------------------------
# RPG Maker: архив без ключа шифрования (System.json)
# ---------------------------------------------------------------------------

BUG_RM_NOKEY = {
    "id": "rm-extract-without-system-json",
    "было": "extract делал early-return без System.json → «0 файлов»",
    "стало": "отсутствие ключа не отменяет извлечение незашифрованных данных",
    "тест": "tests/test_regress.py::TestRPGMaker::test_extract_without_system_json",
}


def build_rm_nokey(root: Path) -> Path:
    """XP-игра: data + картинки лежат открыто, System.json нет."""
    root = lib.ensure_dir(root)
    lib.write(root / "Game.rgssad", lib.rgss_v1([
        ("Data/Actors.rvdata", lib.det_bytes(48, "actors")),
        ("Graphics/System/Window.png", lib.png_stub(8, 8)),
    ]))
    lib.write(root / "Audio/BGM/theme.ogg", lib.ogg_stub(200))
    lib.write_expected(root, "expected.json", {
        "has_key": False,
        "expected_files": ["Audio/BGM/theme.ogg"],
        "rgss_entries": ["Data/Actors.rvdata", "Graphics/System/Window.png"],
    })
    return root


# ---------------------------------------------------------------------------
# RPG Maker: v1-архив, подписанный байтом 1, но с файлом, длина которого
# не кратна 4 (обрезка при расшифровке)
# ---------------------------------------------------------------------------

BUG_RM_V3_WRAP = {
    "id": "rm-rgss-v1-nonmultiple-of-4",
    "было": "размер файла не кратен 4 → лишние байты в хвосте, файл «поехал»",
    "стало": "расшифровка по словам, результат обрезается до объявленного размера",
    "тест": "tests/test_regress.py::TestRPGMaker::test_odd_sized_entry_is_truncated",
}


def build_rm_v3_wrap(root: Path) -> Path:
    root = lib.ensure_dir(root)
    odd = b"ODD" + lib.det_bytes(9, "odd")            # 12 Б — кратно 4
    payload = b"XY" + lib.det_bytes(14, "odd2")       # 16 Б — кратно
    tricky = lib.det_bytes(7, "seven")                # 7 Б — НЕ кратно
    archive = lib.rgss_v1([("Data/Actors.rvdata", odd),
                           ("Data/Map001.rvdata", payload),
                           ("Data/odd7.bin", tricky)])
    lib.write(root / "Game.rgssad", archive)
    expected = {
        "entries": {"Data/Actors.rvdata": lib.hashlib.sha256(odd).hexdigest(),
                    "Data/Map001.rvdata": lib.hashlib.sha256(payload).hexdigest(),
                    "Data/odd7.bin": lib.hashlib.sha256(tricky).hexdigest()},
        "sizes": {"Data/odd7.bin": len(tricky)},
    }
    lib.write_expected(root, "expected.json", expected)
    return root


BUG_RM_V3_MULTI = {
    "id": "rm-rgss-v3-index-then-data",
    "было": "индекс v3 читался вперемешку с данными → вторая запись и далее терялись",
    "стало": "весь индекс подряд, данные — по абсолютным offset; все записи на месте",
    "тест": "tests/test_regress.py::TestRPGMakerV3::test_v3_multiple_entries",
}


def build_rm_v3_multi(root: Path) -> Path:
    root = lib.ensure_dir(root)
    files = [("Data/Actors.rvdata", b"0123456789ab"),
             ("Data/Map001.rvdata", b"hello"),
             ("Graphics/System/Window.png", lib.png_stub(4, 4))]
    lib.write(root / "Game.rgss3a", lib.rgss_v3(files))
    lib.write_expected(root, "expected.json", {
        "entries": [n for n, _ in files],
        "sha256": {n: lib.hashlib.sha256(d).hexdigest() for n, d in files},
    })
    return root


# ---------------------------------------------------------------------------
# Ren'Py: .rpyc старого формата (сигнатура до Marhsal-64)
# ---------------------------------------------------------------------------

BUG_RENPY_OLD_RPYC = {
    "id": "renpy-old-rpyc-signature",
    "было": "старый .rpyc («\\x00 + длина имени») считался Marhsal-64 и падал",
    "стало": "формат определяется по сигнатуре; старый разбирается отдельно",
    "тест": "tests/test_regress.py::TestRenPy::test_old_rpyc_is_recognised",
}


def build_renpy_old_rpyc(root: Path) -> Path:
    root = lib.ensure_dir(root)
    script = lib.rpyc_blob("game/script.rpy", lib.det_bytes(32, "rpyc-old"),
                           legacy=True)
    lib.write(root / "game" / "script.rpyc", script)
    lib.write(root / "game" / "script.rpy", b"label start:\n    return\n")
    lib.write_expected(root, "expected.json", {
        "rpyc": "game/script.rpyc",
        "legacy": True,
        "size": len(script),
        "sha256": lib.hashlib.sha256(script).hexdigest(),
    })
    return root


# ---------------------------------------------------------------------------
# Ren'Py: RPA-3.2 с префиксом ключа у имени
# ---------------------------------------------------------------------------

BUG_RENPY_SLOT2 = {
    "id": "renpy-rpa32-name-prefix",
    "было": "в RPA-3.2 hex-префикс ключа прилипал к имени файла",
    "стало": "префикс отрезается, имя совпадает с настоящим путём",
    "тест": "tests/test_regress.py::TestRenPy::test_rpa32_key_prefix_stripped",
}


def build_renpy_rpa32(root: Path) -> Path:
    root = lib.ensure_dir(root)
    key = 0x2A4F1C3D
    files = {"game/audio/clock.ogg": lib.ogg_stub(300),
             "game/images/bg.png": lib.png_stub(16, 16)}
    blob = bytearray()
    entries = []
    for name, payload in files.items():
        offset = len(blob)
        blob += payload
        entries.append((name, offset, len(payload)))
    index_lines = []
    for name, offset, length in entries:
        prefix = b"%08x " % (0xBEEF0000 + offset)
        index_lines.append(b"%08x %08x " % (offset ^ key, length ^ key)
                           + prefix + name.encode("utf-8"))
    index = zlib.compress(b"\n".join(index_lines) + b"\n")
    header_len = len(b"RPA-3.2 %08x %08x\n" % (0, 0))
    index_offset = header_len + len(blob)
    header = b"RPA-3.2 %08x %08x\n" % (index_offset, key)
    archive = header + bytes(blob) + index
    lib.write(root / "game" / "archive.rpa", archive)
    lib.write_expected(root, "expected.json", {
        "archive": "game/archive.rpa",
        "entries": sorted(files),
        "sha256": {name: lib.hashlib.sha256(data).hexdigest()
                   for name, data in files.items()},
    })
    return root


# ---------------------------------------------------------------------------
# Unreal: .pak v10 — запись-битфилд + FDI
# ---------------------------------------------------------------------------

BUG_UE_V10_FDI = {
    "id": "ue-pak-v10-bitfield-record",
    "было": "запись v10 читалась как v8 (метод/блоки не из битфилда) → мусор",
    "стало": "битфилд: 0-5 block_size, 6-21 block_count, 22 enc, 23-28 метод, 29-31 размеры",
    "тест": "tests/test_regress.py::TestUnreal::test_v10_record_layout",
}


def build_ue_v10(root: Path) -> Path:
    root = lib.ensure_dir(root)
    files = {"Game/Content/Maps/Entry.umap": lib.det_bytes(64, "umap"),
             "Game/Content/Data/Table.uasset": lib.det_bytes(96, "uasset")}
    pak = lib.unreal_pak_v10(list(files.items()))
    lib.write(root / "pakchunk0-Linux.pak", pak)
    lib.write_expected(root, "expected.json", {
        "pak_version": 10,
        "files": sorted(files),
        "sha256": {name: lib.hashlib.sha256(data).hexdigest()
                   for name, data in files.items()},
    })
    return root


# ---------------------------------------------------------------------------
# Generic: целые числа в pak.json-подобном формате (ключ без "None")
# ---------------------------------------------------------------------------

BUG_GENERIC_PAK_JSON = {
    "id": "ue-method-table-without-none",
    "было": "таблица методов без None читалась 0-based → всё смещено на 1",
    "стало": "1-based, если names[0] не None/-/''; 0-based только при явном None",
    "тест": "tests/test_regress.py::TestGeneric::test_method_table_zero_based_only_when_none",
}


def build_generic_pak_json(root: Path) -> Path:
    """Не .pak, а описание: таблицы методов, на которых спотыкался парсер."""
    root = lib.ensure_dir(root)
    cases = {
        "with_none": {"names": ["None", "Zlib", "LZ4", "Oodle"],
                      "expected": {0: "none", 1: "zlib", 2: "lz4", 3: "oodle"}},
        "without_none": {"names": ["Zlib", "LZ4", "Oodle", "None"],
                         "expected": {0: "none", 1: "zlib", 2: "lz4", 3: "oodle"}},
        # пустая строка в слоте 0 трактуется как «таблица с нуля» (None/-/'' );
        # метод за пределами таблицы — пустая строка, а НЕ выдуманный метод
        "empty_first": {"names": ["", "Zlib"],
                        "expected": {0: "none", 1: "zlib", 2: ""}},
    }
    lib.write_expected(root, "expected.json", cases)
    lib.write(root / "README.txt", b"table-only fixture; see test_regress.py\n")
    return root


#: Все регресс-фикстуры живут под ``tests/fixtures/regress/`` — отдельно от
#: основных стендов. Иначе они попадают в рекурсивный скан стенда и ломают
#: тесты, которые ждут ровно один data.win / один pak.
BUILDERS = {
    "regress/gm/regress_abs_strings": build_gm_strg_abs,
    "regress/gm/regress_tpag_align": build_gm_tpag,
    "regress/rm/regress_nokey": build_rm_nokey,
    "regress/rm/regress_v3_wrap": build_rm_v3_wrap,
    "regress/rm/regress_v3_multi": build_rm_v3_multi,
    "regress/renpy/regress_old_rpyc": build_renpy_old_rpyc,
    "regress/renpy/regress_slot2_only": build_renpy_rpa32,
    "regress/ue/regress_v10_fdi": build_ue_v10,
    "regress/generic/regress_pak_json": build_generic_pak_json,
}

BUG_CASES = {
    "regress/gm/regress_abs_strings": BUG_GM_ABS_STRINGS,
    "regress/gm/regress_tpag_align": BUG_GM_TPAG,
    "regress/rm/regress_nokey": BUG_RM_NOKEY,
    "regress/rm/regress_v3_wrap": BUG_RM_V3_WRAP,
    "regress/rm/regress_v3_multi": BUG_RM_V3_MULTI,
    "regress/renpy/regress_old_rpyc": BUG_RENPY_OLD_RPYC,
    "regress/renpy/regress_slot2_only": BUG_RENPY_SLOT2,
    "regress/ue/regress_v10_fdi": BUG_UE_V10_FDI,
    "regress/generic/regress_pak_json": BUG_GENERIC_PAK_JSON,
}
