"""Смоук-тесты на синтетическом стенде (python -m unittest discover tests)."""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from salvage.core.model import Dataset
from salvage.core.plugin_base import EngineContext
from salvage.core.registry import build_registry, detect_all
from salvage.core.util import safe_rel
from salvage.plugins.rpgmaker.plugin import decrypt_mv

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


def ensure_fixtures() -> None:
    if not (FIX / "unity").is_dir():
        import make_fixtures
        make_fixtures.main()


def best_engine(path: Path) -> str:
    hits = detect_all(path)
    return hits[0][0].slug if hits else "generic"


class TestFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        ensure_fixtures()
        cls.reg = build_registry()
        cls.tmp = Path(tempfile.mkdtemp(prefix="salvage-test-"))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    # --- детект ---------------------------------------------------------
    def test_detect_all_engines(self) -> None:
        expected = {
            "unity": "unity", "godot": "godot", "gm": "gamemaker",
            "rm_mv": "rpgmaker", "renpy": "renpy",
        }
        for fixture, slug in expected.items():
            with self.subTest(fixture=fixture):
                self.assertEqual(best_engine(FIX / fixture), slug)

    def test_safe_rel_blocks_traversal(self) -> None:
        self.assertEqual(safe_rel("../../etc/passwd"), "etc/passwd")
        self.assertEqual(safe_rel("a/../../b/c.txt"), "a/b/c.txt")
        self.assertNotIn("..", safe_rel("x/../../../y"))

    # --- RPG Maker MV: расшифровка ---------------------------------------
    def test_mv_decrypt(self) -> None:
        key = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
        plain = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 2
        head = bytearray(plain[:16])
        for i in range(16):
            head[i] ^= key[i]
        enc = b"RPGMV" + b"\x00" * 11 + bytes(head) + plain[16:]
        self.assertEqual(decrypt_mv(enc, key), plain)

    def test_mv_extract_roundtrip(self) -> None:
        plugin = self.reg["rpgmaker"]
        ds = plugin.scan(FIX / "rm_mv", EngineContext(deep=False, log=lambda m: None))
        self.assertTrue(any(a.extra.get("encrypted") for a in ds.assets))
        out = self.tmp / "mv"
        summary = plugin.extract(ds, out, EngineContext(log=lambda m: None))
        self.assertGreaterEqual(summary["extracted"], 3)
        pngs = list((out / "decrypted").rglob("*.png"))
        self.assertTrue(pngs, "должны появиться расшифрованные .png")
        self.assertTrue(pngs[0].read_bytes().startswith(b"\x89PNG"))
        oggs = list((out / "decrypted").rglob("*.ogg"))
        self.assertTrue(oggs and oggs[0].read_bytes().startswith(b"OggS"))

    # --- Godot PCK --------------------------------------------------------
    def test_godot_pck(self) -> None:
        plugin = self.reg["godot"]
        ds = plugin.scan(FIX / "godot", EngineContext(deep=True, log=lambda m: None))
        entries = [a for a in ds.assets if a.container]
        self.assertGreaterEqual(len(entries), 5)
        self.assertTrue(all(not a.path.startswith("res://") for a in entries))
        out = self.tmp / "godot"
        summary = plugin.extract(ds, out, EngineContext(log=lambda m: None))
        self.assertGreaterEqual(summary["extracted"], 5)
        icon = list(out.rglob("icon.png"))
        self.assertTrue(icon and icon[0].read_bytes().startswith(b"\x89PNG"))

    # --- Ren'Py RPA -------------------------------------------------------
    def test_renpy_rpa(self) -> None:
        plugin = self.reg["renpy"]
        ds = plugin.scan(FIX / "renpy", EngineContext(deep=False, log=lambda m: None))
        entries = [a for a in ds.assets if a.container]
        self.assertEqual(len(entries), 3)
        out = self.tmp / "renpy"
        summary = plugin.extract(ds, out, EngineContext(log=lambda m: None))
        # 3 файла из RPA + script.rpyc; сам .rpa не дублируется (skip_kinds)
        self.assertEqual(summary["extracted"], 4)
        self.assertFalse(list((out / "files").rglob("*.rpa")), "архив не должен копироваться дважды")
        names = {p.name for p in (out / "rpa").rglob("*") if p.is_file()}
        self.assertIn("bg room.png", names)
        self.assertIn("theme.ogg", names)

    # --- GameMaker --------------------------------------------------------
    def test_gamemaker_chunks(self) -> None:
        plugin = self.reg["gamemaker"]
        ds = plugin.scan(FIX / "gm", EngineContext(deep=True, log=lambda m: None))
        gm = ds.meta.get("gamemaker") or {}
        tags = [c["tag"] for c in gm.get("chunks", [])]
        self.assertEqual(tags, ["GEN8", "SPRT", "TXTR", "STRG"])
        self.assertEqual(gm.get("project_resources", {}).get("GMSprite"), 1)

    # --- Unity: deep-скан не должен ронять процесс --------------------------
    def test_unity_deep_degrades_gracefully(self) -> None:
        # через оркестратор: он прогоняет анализаторы секретов/дубликатов
        from salvage.core.scan import scan as scan_game
        ds, plugin = scan_game(FIX / "unity", "unity",
                               EngineContext(deep=True, log=lambda m: None))
        self.assertGreater(len(ds.assets), 5)
        self.assertIn("unity", ds.meta)
        secrets = ds.meta.get("secrets") or {}
        self.assertTrue(secrets.get("api_key"), "ожидался api_key из settings.json")
        # sklearn-стиль: пути битых ссылок не должны падать даже без зависимостей
        self.assertIsInstance(ds.meta.get("dependencies", 0), (int, type(None)))

    # --- отчёты -----------------------------------------------------------
    def test_reports(self) -> None:
        from salvage.report.export import write_json, write_markdown
        from salvage.report.html import write_html

        plugin = self.reg["generic"]
        ds = Dataset("generic", "Generic", FIX / "gd_nonexistent")
        ds.add_asset("a/b.png", "texture", 100)
        ds.add_finding("warn", "x", "Тест")
        j = write_json(ds, self.tmp / "r" / "scan.json")
        h = write_html(ds, self.tmp / "r" / "report.html")
        m = write_markdown(ds, self.tmp / "r" / "report.md")
        data = json.loads(j.read_text("utf-8"))
        self.assertEqual(data["totals"]["files"], 1)
        self.assertIn("<!doctype html>", h.read_text("utf-8").lower())
        self.assertIn("# Аудит", m.read_text("utf-8"))

    # --- CLI ----------------------------------------------------------------
    def test_cli_scan_exit_codes(self) -> None:
        from salvage.cli import main
        out = self.tmp / "cli"
        code = main(["scan", str(FIX / "godot"), "--out", str(out), "--formats", "json"])
        self.assertIn(code, (0, 1, 2))
        self.assertTrue((out / "scan.json").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
