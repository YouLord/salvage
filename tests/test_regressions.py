"""Регресс-тесты: на каждый исправленный баг — минимальная фикстура.

Каждый кейс собирается в temp-каталог через ``make_fixtures.build_one(...,
with_bug=True)`` — это и есть минимальная игра, на которой баг воспроизводился.
Смысл: если кто-то вернёт старое поведение, тест упадёт на минимальной фикстуре,
а не на большом стенде (где причину искать дольше).
"""
from __future__ import annotations

import hashlib
import importlib
import json
import random
import shutil
import tempfile
import unittest
from pathlib import Path

from salvage.core.plugin_base import EngineContext
from salvage.core.registry import build_registry

HERE = Path(__file__).resolve().parent
if str(HERE) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(HERE))
FIX = HERE / "fixtures"

MODULES = {
    "gm": "make_fixture_gamemaker",
    "rm_xp": "make_fixture_rpgmaker_xp",
    "renpy": "make_fixture_renpy",
    "ue": "make_fixture_unreal",
}


def build_minimal(alias: str, base: Path) -> Path:
    mod = importlib.import_module(MODULES[alias])
    root = base / alias
    return mod.build(root, with_bug=True)


def tree_digest(root: Path) -> dict[str, str]:
    out = {}
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out[str(p.relative_to(root))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


class TestRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reg = build_registry()
        cls.tmp = Path(tempfile.mkdtemp(prefix="salvage-regress-"))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_regression_gm_external_audiogroup(self) -> None:
        """Баг: audiogroup1.dat считался data-файлом → звук терялся."""
        game = build_minimal("gm", self.tmp)
        self.assertEqual(sorted(p.name for p in game.iterdir()),
                         ["audiogroup1.dat", "data.win"])
        plugin = self.reg["gamemaker"]
        ctx = EngineContext(deep=True, log=lambda m: None)
        ds = plugin.scan(game, ctx)
        gm = ds.meta.get("gamemaker") or {}
        self.assertTrue(gm.get("audio_groups"), "внешняя аудиогруппа не разобрана")
        out = self.tmp / "gm_bug_out"
        plugin.extract(ds, out, EngineContext(log=lambda m: None))
        music = out / "audio" / "sn_music.ogg"
        self.assertTrue(music.is_file(), "звук из audiogroup1.dat не извлечён")
        self.assertTrue(music.read_bytes().startswith(b"OggS"))

    def test_regression_rm_without_system_json(self) -> None:
        """Баг: extract без System.json/ключа делал early-return → «0 файлов»."""
        game = build_minimal("rm_xp", self.tmp)
        self.assertTrue((game / "Game.rgssad").is_file())
        self.assertFalse((game / "System.json").exists())
        plugin = self.reg["rpgmaker"]
        ds = plugin.scan(game, EngineContext(deep=True, log=lambda m: None))
        out = self.tmp / "rm_bug_out"
        summary = plugin.extract(ds, out, EngineContext(log=lambda m: None))
        self.assertGreaterEqual(summary["extracted"], 4, "RGSS не извлечён без ключа")
        self.assertTrue(list((out / "rgss").rglob("*.png")))

    def test_regression_ue_offset_semantics(self) -> None:
        """Баг: данные читались прямо с offset записи, без её заголовка.

        Настоящий .pak: offset → заголовок записи, данные — после него.
        Если вернуть старое поведение, zlib/ LZ4 сразу сломаются на неверных байтах.
        """
        import importlib
        from salvage.plugins.generic import unreal_pak
        mod = importlib.import_module("make_fixture_unreal")
        game = Path(tempfile.mkdtemp(prefix="ue-bug-", dir=self.tmp)) / "ue"
        mod.build(game, with_bug=True)
        pak = unreal_pak.read_pak(game / "pakchunk0-WindowsNoEditor.pak")
        self.assertEqual(len(pak.entries), 3)
        for e in pak.entries:
            self.assertGreater(e.header_size, 0, "не вычислен размер заголовка записи")
            self.assertNotEqual(e.offset, e.data_offset)
            data, status = unreal_pak.read_entry_data(pak, e)
            self.assertEqual(status, "ok", f"{e.name}: {status}")
            self.assertTrue(data is not None and len(data) == e.uncompressed)

    def test_rgss_version2_semantics(self) -> None:
        """Версии 2 формата не существует: VX пишет 0x01, а не 0x02.

        Эталон (rpgo / RPGMakerDecrypter): .rgss2a объявляет версию 1 и
        использует схему XP. Стенд держит три случая: родной 0x01, патченный
        0x02 (читается той же схемой) и 0x03 (не должен выдавать файлы).
        """
        import hashlib
        import json

        from salvage.plugins.rpgmaker import plugin as rm

        root = FIX / "rm_xp"
        expected = json.loads((root / "expected_rgss_v2.json").read_text("utf-8"))
        for name, magic in (("Game.rgss2a", 1), ("vx_b2.rgss2a", 2)):
            path = root / name
            head = path.read_bytes()[:8]
            self.assertEqual(head[7], magic, f"{name}: байт версии")
            with open(path, "rb") as f:
                entries = rm.parse_rgss_entries(f, head[7])
            got = {e["name"]: e for e in entries or []}
            self.assertEqual(set(got), set(expected), f"{name}: состав файлов")
            raw = path.read_bytes()
            for fname, sha in expected.items():
                e = got[fname]
                blob = raw[e["offset"]:e["offset"] + e["size"]]
                dec = rm.decrypt_words(blob, e["key"])
                # длина уже кратна 4 в фикстуре; сверяем sha256 распакованного
                self.assertEqual(hashlib.sha256(dec).hexdigest(), sha, fname)

        # байт 3 у .rgss2a — это НЕ v3-схема: ничего не выдумываем
        weird = root / "vx_b3.rgss2a"
        with open(weird, "rb") as f:
            entries = rm.parse_rgss_entries(f, 3)
        self.assertEqual(entries, [], "v3-схема не должна находить файлы в v1-архиве")

    def test_fixtures_deterministic(self) -> None:
        """Бинарные фикстуры должны пересобираться в те же байты."""
        a = Path(tempfile.mkdtemp(prefix="fix-a-", dir=self.tmp))
        b = Path(tempfile.mkdtemp(prefix="fix-b-", dir=self.tmp))
        for alias in ("gm", "rm_xp", "ue", "renpy"):
            mod = importlib.import_module(MODULES[alias])
            random.seed(7)
            mod.build(a / alias)
            random.seed(7)
            mod.build(b / alias)
        self.assertEqual(tree_digest(a), tree_digest(b))

    def test_bug_cases_documented(self) -> None:
        """У каждого регресс-кейса есть описание и ссылка на тест."""
        for alias in MODULES:
            mod = importlib.import_module(MODULES[alias])
            case = getattr(mod, "BUG_CASE", None)
            if case is None:
                continue
            for key in ("id", "было", "стало", "тест"):
                self.assertIn(key, case, f"{alias}: нет поля {key}")
            test_name = case["тест"].split("::")[-1]
            self.assertTrue(hasattr(self, test_name),
                            f"{alias}: тест {test_name} не найден")


if __name__ == "__main__":
    unittest.main(verbosity=2)
