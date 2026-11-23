"""Регресс-тесты на конкретные баги: один тест = одна минимальная «больная» игра.

Каждая фикстура собирается ``tests/fixtures_regress.py`` — байты пишутся по
спецификации вручную, без вызова разбираемого кода. Смысл в том, что если кто-то
вернёт старое (сломанное) поведение, упадёт не общий стенд, а маленькая игра с
ровно одним отличием — и в сообщении сразу видно, ЧТО сломалось и почему.

В каждом классе в docstring — какой именно баг закрывается (было → стало).
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import fixtures_regress as reg  # noqa: E402

from salvage.core.plugin_base import EngineContext  # noqa: E402

ctx = EngineContext(deep=True, log=lambda m: None)


class _Fixture(unittest.TestCase):
    """Общая обвязка: каталог в temp, сборка фикстуры, сверка sha256."""

    name = ""

    @classmethod
    def setUpClass(cls) -> None:
        cls._root = Path(tempfile.mkdtemp(prefix="salvage-regress-"))
        cls.root = cls._root / cls.name.replace("/", "_")
        reg.BUILDERS[cls.name](cls.root)
        expected = cls.root / "expected.json"
        cls.expected = json.loads(expected.read_text("utf-8")) if expected.exists() else {}

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._root, ignore_errors=True)

    def sha(self, path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------


class TestGameMakerSTRG(_Fixture):
    """Баг: STRG хранил абсолютные адреса, парсер читал их как относительные.

    Было: все имена ресурсов (obj_*/rm_*/snd_*) терялись, в манифесте — пусто.
    Стало: пробуются базы (abs, payload, header), имена на месте и совпадают
    с ожидаемыми ровно, а не «какое-то имя нашлось».
    """

    name = "regress/gm/regress_abs_strings"

    def test_strings_are_read(self) -> None:
        from salvage.core.registry import build_registry

        ds = build_registry()["gamemaker"].scan(self.root, ctx)
        strings = (ds.meta.get("gamemaker") or {}).get("strings") or []
        self.assertEqual(strings, self.expected["strings"],
                         "имена ресурсов должны читаться из STRG с абсолютными адресами")

    def test_fixture_matches_expected_bytes(self) -> None:
        self.assertEqual(self.sha(self.root / "data.win"), self.expected["sha256"])


class TestGameMakerTPAG(_Fixture):
    """Баг: TPAG читался записью неверной длины.

    Было: x/y/w/h съезжали (16- или 28-байтовая запись вместо 24), номер
    текстуры указывал не туда, ректы кадров не совпадали с картинками.
    Стало: запись 24 Б (10×u16 + u32 tex), все три ректа совпадают.
    """

    name = "regress/gm/regress_tpag_align"

    def test_rects_are_byte_exact(self) -> None:
        from salvage.core.registry import build_registry

        ds = build_registry()["gamemaker"].scan(self.root, ctx)
        tpag = (ds.meta.get("gamemaker") or {}).get("tpag_full") or []
        got = [{"x": it["x"], "y": it["y"], "w": it["w"], "h": it["h"],
                "tex": it["tex"]} for it in tpag if it]
        self.assertEqual(got, self.expected["rects"])


class TestRPGMakerWithoutKey(_Fixture):
    """Баг: extract без System.json делал early-return и отчитывался «0 файлов».

    Было: игра без ключа шифрования давала пустое извлечение.
    Стало: отсутствие ключа не отменяет копирование незашифрованных файлов,
    и они действительно есть на диске.
    """

    name = "regress/rm/regress_nokey"

    def test_extract_without_system_json(self) -> None:
        from salvage.core.registry import build_registry

        dest = self.root / "out"
        plugin = build_registry()["rpgmaker"]
        ds = plugin.scan(self.root, ctx)
        summary = plugin.extract(ds, dest, ctx, None)
        self.assertGreater(summary["extracted"], 0, "файлы должны извлекаться и без ключа")
        for rel in self.expected["expected_files"]:
            self.assertTrue((dest / "files" / rel).is_file(), f"нет {rel}")


class TestRPGMakerOddSizes(_Fixture):
    """Баг: размер файла не кратен 4 → в хвосте лишние байты.

    Было: размер после расшифровки округлялся вверх (или вниз) — файл
    «поехал» или обрезался на 1–3 байта.
    Стало: расшифровка по словам с обрезкой строго до объявленного размера.
    """

    name = "regress/rm/regress_v3_wrap"

    def test_odd_sized_entry_is_truncated(self) -> None:
        from salvage.plugins.rpgmaker import plugin as rm

        with open(self.root / "Game.rgssad", "rb") as f:
            entries = rm.parse_rgss_entries(f, 1)
            self.assertEqual({e["name"]: e["size"] for e in entries},
                             {"Data/Actors.rvdata": 12, "Data/Map001.rvdata": 16,
                              "Data/odd7.bin": 7})
            for e in entries:
                f.seek(e["offset"])
                data = rm.decrypt_words(f.read(e["size"]), e["key"])
                self.assertEqual(hashlib.sha256(data).hexdigest(),
                                 self.expected["entries"][e["name"]],
                                 f"{e['name']}: байты после расшифровки")


class TestRPGMakerV3(_Fixture):
    """Смежный контроль: v3 (Ace) с несколькими файлами.

    Баг, который здесь ловится: индекс v3 читался «вперемешку» с данными,
    поэтому вторая запись и далее терялись (на стенде был только 1 файл).
    """

    name = "regress/rm/regress_v3_multi"

    def test_v3_multiple_entries(self) -> None:
        from salvage.plugins.rpgmaker import plugin as rm

        with open(self.root / "Game.rgss3a", "rb") as f:
            self.assertEqual(f.read(8)[7], 3)
            entries = rm.parse_rgss_entries(f, 3)
            self.assertEqual([e["name"] for e in entries], self.expected["entries"],
                             "индекс v3 идёт целиком до данных — все записи на месте")
            for e in entries:
                f.seek(e["offset"])
                data = rm.decrypt_words(f.read(e["size"]), e["key"])
                self.assertEqual(hashlib.sha256(data).hexdigest(),
                                 self.expected["sha256"][e["name"]], e["name"])


class TestRenPyOldRpyc(_Fixture):
    """Баг: старый .rpyc (zlib-поток без RPC2) считался Marhsal-64 и падал.

    Было: исключение на первом же файле → декомпиляция всего проекта вставала.
    Стало: формат определяется по сигнатуре; старый контейнер разбирается,
    ошибка (если данные действительно битые) — честная и на конкретном файле.
    """

    name = "regress/renpy/regress_old_rpyc"

    def test_old_rpyc_is_recognised(self) -> None:
        from salvage.core import rpyc

        raw = (self.root / "game" / "script.rpyc").read_bytes()
        self.assertFalse(raw.startswith(rpyc.RPYC_MAGIC), "фикстура должна быть старым форматом")
        with self.assertRaises(rpyc.RpycError):
            # здесь payload намеренно не pickle — проверяем честную ошибку,
            # а не тихий «успешный» разбор мусора
            rpyc.decompile_file(self.root / "game" / "script.rpyc", None)


class TestRenPyRPA32(_Fixture):
    """Баг: в RPA-3.2 hex-префикс ключа прилипал к имени файла.

    Было: имена вида «beef0012 images/bg.png», извлечение в кривые пути.
    Стало: префикс отрезается, имена — настоящие пути, содержимое совпадает.
    """

    name = "regress/renpy/regress_slot2_only"

    def test_rpa32_key_prefix_stripped(self) -> None:
        from salvage.core.registry import build_registry

        ds = build_registry()["renpy"].scan(self.root, ctx)
        rpa = (ds.meta.get("rpa") or [{}])[0]
        self.assertEqual(rpa.get("version"), "3.2")
        self.assertEqual(rpa.get("entries"), len(self.expected["entries"]))
        names = sorted(a.path for a in ds.assets if a.container)
        self.assertEqual(names, self.expected["entries"],
                         "имена в индексе без hex-префикса")


class TestUnrealV10(_Fixture):
    """Баг: запись v10 читалась как v8, а FDI искали внутри индекса.

    Было: у записей мусор вместо offset/size; FDI — отдельный блок файла,
    ссылки на него абсолютные, поэтому список файлов был пуст.
    Стало: битфилд + FDI из файла по абсолютному смещению; имена и байты точные.
    """

    name = "regress/ue/regress_v10_fdi"

    def test_v10_record_layout(self) -> None:
        from salvage.plugins.generic import unreal_pak

        pak = unreal_pak.read_pak(self.root / "pakchunk0-Linux.pak")
        self.assertEqual(pak.version, self.expected["pak_version"])
        self.assertEqual(sorted(e.name for e in pak.entries), self.expected["files"])
        for e in pak.entries:
            data, status = unreal_pak.read_entry_data(pak, e)
            self.assertEqual(status, "ok", e.name)
            self.assertEqual(hashlib.sha256(data).hexdigest(),
                             self.expected["sha256"][e.name], e.name)


class TestGenericMethodTables(_Fixture):
    """Баг: таблица методов без None читалась 0-based → всё смещено на 1.

    Было: method=1 в паках без «None» давал Zlib вместо… имени по факту
    не было вовсе; сжатые данные распаковывались не тем методом.
    Стало: 1-based по умолчанию, 0-based только при явном None/-/'' в names[0].
    """

    name = "regress/generic/regress_pak_json"

    def test_method_table_zero_based_only_when_none(self) -> None:
        from salvage.plugins.generic.unreal_pak import method_name

        for case, spec in self.expected.items():
            names = spec["names"]
            for method, want in spec["expected"].items():
                got = method_name(int(method), names, 8)
                self.assertEqual(got, want, f"{case}: method={method} names={names}")


class TestRegressCatalog(unittest.TestCase):
    """Мета-проверка: у каждой регресс-фикстуры есть описание бага и тест."""

    def test_every_builder_has_bug_case(self) -> None:
        self.assertEqual(set(reg.BUILDERS), set(reg.BUG_CASES))
        for name, case in reg.BUG_CASES.items():
            for key in ("id", "было", "стало", "тест"):
                self.assertIn(key, case, f"{name}: нет поля {key}")
            self.assertTrue(case["тест"].startswith("tests/test_regress.py::"),
                            f"{name}: ссылка на тест должна быть в этом файле")

    def test_bug_ids_are_unique(self) -> None:
        ids = [c["id"] for c in reg.BUG_CASES.values()]
        self.assertEqual(len(ids), len(set(ids)), "id регресс-кейсов должны быть уникальны")

    def test_thin_wrappers_export_cases(self) -> None:
        import importlib

        for mod_name in ("make_fixture_gamemaker_regress",
                         "make_fixture_rpgmaker_regress",
                         "make_fixture_renpy_regress"):
            mod = importlib.import_module(mod_name)
            self.assertTrue(callable(mod.build), mod_name)
            self.assertTrue(mod.BUG_CASE, f"{mod_name}: пустой BUG_CASE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
