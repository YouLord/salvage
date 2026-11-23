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
            "rm_mv": "rpgmaker", "rm_xp": "rpgmaker", "renpy": "renpy",
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
        # 3 из RPA + 2 .rpyc (+ декомпиляция); сам .rpa не дублируется
        self.assertGreaterEqual(summary["extracted"], 5)
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
        for expected in ("GEN8", "SPRT", "TPAG", "TXTR", "SOND", "AUDO", "STRG"):
            self.assertIn(expected, tags)
        self.assertEqual(gm.get("project_resources", {}).get("GMSprite"), 1)
        # новый функционал: строки, спрайты, звуки, форматы текстур
        self.assertGreaterEqual(len(gm.get("strings", [])), 8)
        self.assertEqual(gm.get("sprite_frames"), 2)
        self.assertIn("png", gm.get("texture_formats", {}))
        self.assertIn("qoi", gm.get("texture_formats", {}))
        self.assertIn("bz2", gm.get("texture_formats", {}))
        self.assertTrue(gm.get("audio_groups"), "внешняя аудиогруппа должна быть разобрана")

    def test_gamemaker_extract_textures_audio_manifest(self) -> None:
        plugin = self.reg["gamemaker"]
        ds = plugin.scan(FIX / "gm", EngineContext(deep=True, log=lambda m: None))
        out = self.tmp / "gm"
        summary = plugin.extract(ds, out, EngineContext(log=lambda m: None))
        self.assertGreaterEqual(summary["extracted"], 8)
        # три страницы: PNG/QOI/BZ2 — все приводятся к PNG
        pngs = sorted((out / "textures").glob("tex_*.png"))
        self.assertEqual(len(pngs), 3)
        for png in pngs:
            self.assertTrue(png.read_bytes().startswith(b"\x89PNG"), png.name)
        # кадры спрайта нарезаны
        frames = list((out / "sprites").glob("spr_player_*.png"))
        self.assertEqual(len(frames), 2)
        # аудио: встроенное + из внешней аудиогруппы
        audio = {p.name for p in (out / "audio").glob("*")}
        self.assertIn("sn_click.ogg", audio)
        self.assertIn("sn_music.ogg", audio)
        # манифест
        man = json.loads((out / "manifest.json").read_text("utf-8"))
        self.assertEqual(man["counts"]["textures"], 3)
        self.assertEqual(man["counts"]["sprites"], 1)
        self.assertEqual(man["objects"], ["obj_player"])
        self.assertEqual(man["rooms"], ["rm_room"])
        self.assertEqual(man["scripts"], ["scr_move"])
        self.assertEqual(man["shaders"], ["sh_pass"])
        self.assertTrue((out / "strings.txt").is_file())

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

    # --- RGSS (XP/VX/Ace) ---------------------------------------------------
    def test_rgss_v1_v3(self) -> None:
        import io
        from salvage.plugins.rpgmaker.plugin import parse_rgss_entries, extract_rgss_file
        for fname, version, expected in (("Game.rgssad", 1, 4), ("Game.rgss3a", 3, 3)):
            path = FIX / "rm_xp" / fname
            with open(path, "rb") as f:
                entries = parse_rgss_entries(f, version)
            self.assertIsNotNone(entries, fname)
            self.assertEqual(len(entries), expected, fname)
            with open(path, "rb") as f:
                for e in entries[:2]:
                    data = extract_rgss_file(f, {"rgss_offset": e["offset"],
                                                 "rgss_key": e["key"],
                                                 "rgss_size": e["size"]})
                    self.assertIsNotNone(data, f"{fname}:{e['name']}")
                    self.assertTrue(data.startswith((b"\x89PNG", b"OggS", b"\x04\x08")),
                                    f"{fname}:{e['name']} head={data[:6]!r}")

    def test_rpgmaker_data_json(self) -> None:
        plugin = self.reg["rpgmaker"]
        ds = plugin.scan(FIX / "rm_xp", EngineContext(deep=True, log=lambda m: None))
        out = self.tmp / "rmxp"
        summary = plugin.extract(ds, out, EngineContext(log=lambda m: None))
        self.assertGreaterEqual(summary["extracted"], 6)
        actors = out / "data_json" / "Data" / "Actors.rxdata.json"
        self.assertTrue(actors.is_file())
        data = json.loads(actors.read_text("utf-8"))
        self.assertEqual(data[1]["__class__"], "RPG::Actor")
        self.assertEqual(data[1]["ivars"]["name"], "Герой")
        # RGSS распакован
        self.assertTrue(list((out / "rgss").rglob("*.png")))

    def test_ruby_marshal_roundtrip(self) -> None:
        from salvage.core import ruby_marshal as rm
        payload = {"actors": [1, 2, 3], "name": "Тест", "big": 2 ** 40, "neg": -123456}
        self.assertEqual(rm.loads(rm.dumps(payload)), payload)
        obj = {"__class__": "RPG::Actor", "ivars": {"id": 7, "name": "Имя"}}
        self.assertEqual(rm.to_jsonable(rm.loads(rm.json_to_marshal(obj))), obj)

    # --- Unreal .pak ----------------------------------------------------------
    def test_unreal_pak(self) -> None:
        summary = self.reg["generic"].scan(FIX / "ue", EngineContext(deep=False, log=lambda m: None))
        paks = summary.meta.get("ue_paks") or []
        self.assertEqual(len(paks), 1)
        self.assertEqual(paks[0]["version"], 3)
        self.assertEqual(paks[0]["entries"], 3)
        self.assertEqual(paks[0]["compression"], ["zlib"])
        out = self.tmp / "ue"
        s = self.reg["generic"].extract(summary, out, EngineContext(log=lambda m: None))
        self.assertEqual(s["extracted"], 3)
        files = sorted(p.name for p in (out / "pak").rglob("*") if p.is_file())
        self.assertIn("T_Rock.uasset", files)

    # --- FMOD FSB5 -------------------------------------------------------------
    def test_fmod_fsb5(self) -> None:
        dataset = self.reg["generic"].scan(FIX / "fmod", EngineContext(deep=False, log=lambda m: None))
        banks = dataset.meta.get("fmod_banks") or []
        self.assertEqual(len(banks), 1)
        self.assertEqual(banks[0]["samples"], 3)
        self.assertEqual(banks[0]["codecs"], {"pcm16": 3})
        out = self.tmp / "fmod"
        s = self.reg["generic"].extract(dataset, out, EngineContext(log=lambda m: None))
        audio = [p for p in (out / "fmod").rglob("*") if p.is_file()]
        self.assertEqual(len(audio), 3)

    # --- Ren'Py RPYC ------------------------------------------------------------
    def test_rpyc_decompile(self) -> None:
        plugin = self.reg["renpy"]
        ds = plugin.scan(FIX / "renpy", EngineContext(deep=False, log=lambda m: None))
        out = self.tmp / "renpy_dec"
        plugin.extract(ds, out, EngineContext(log=lambda m: None))
        scripts = list((out / "decompiled").rglob("*.rpy"))
        self.assertEqual(len(scripts), 2)
        compiled = [p for p in scripts if "compiled" in p.name][0]
        text = compiled.read_text("utf-8")
        self.assertIn("label start:", text)
        self.assertIn("Добро пожаловать в фикстуру!", text)
        self.assertIn("main_menu", text)

    # --- Doctor Mode --------------------------------------------------------------
    def test_doctor_mode(self) -> None:
        from salvage.core.doctor import run_doctor, doctor_markdown
        broken = self.tmp / "broken"
        (broken / "a").mkdir(parents=True)
        (broken / "a" / "bad.png").write_bytes(b"NOTAPNG" + b"\x00" * 32)
        (broken / "a" / "empty.ogg").write_bytes(b"")
        from salvage.core.scan import scan as scan_game
        ds, _ = scan_game(broken, "generic", EngineContext(deep=False, log=lambda m: None))
        rep = run_doctor(ds)
        self.assertLess(rep["score"], 100)
        self.assertEqual(rep["media"]["counts"]["bad_images"], 1)
        self.assertEqual(rep["media"]["counts"]["empty"], 1)
        self.assertIn("Врачебный отчёт", doctor_markdown(rep))

    # --- изображения: QOI/PNG кодеки ------------------------------------------------
    def test_qoi_png_codecs(self) -> None:
        from salvage.core import imaging
        rgba = bytes([(i * 13) & 0xFF for i in range(8 * 8 * 4)])
        qoi = imaging.encode_qoi(rgba, 8, 8)
        self.assertEqual(qoi[:4], b"qoif")
        w, h, back = imaging.decode_qoi(qoi)
        self.assertEqual((w, h), (8, 8))
        self.assertEqual(back, rgba)
        png = imaging.encode_png_rgba(rgba, 8, 8)
        self.assertTrue(png.startswith(b"\x89PNG"))
        inner, kind = imaging.bunzip_if_needed(__import__("bz2").compress(qoi))
        self.assertEqual(kind, "bz2+qoi")
        self.assertEqual(inner, qoi)

    # --- CLI ----------------------------------------------------------------
    def test_cli_scan_exit_codes(self) -> None:
        from salvage.cli import main
        out = self.tmp / "cli"
        code = main(["scan", str(FIX / "godot"), "--out", str(out), "--formats", "json"])
        self.assertIn(code, (0, 1, 2))
        self.assertTrue((out / "scan.json").is_file())

    def test_cli_extract_with_doctor(self) -> None:
        from salvage.cli import main
        out = self.tmp / "cli_extract"
        code = main(["extract", str(FIX / "gm"), "--out", str(out),
                     "--texture-format", "bz2"])
        self.assertIn(code, (0, 1, 2))
        self.assertTrue(list(out.rglob("*.png")), "спрайты должны быть в PNG")

    def test_cli_audit_doctor_report(self) -> None:
        from salvage.cli import main
        out = self.tmp / "cli_audit"
        code = main(["audit", str(FIX / "rm_xp"), "--out", str(out)])
        self.assertIn(code, (0, 1, 2))
        html = (out / "report.html").read_text("utf-8")
        self.assertIn("Врачебный отчёт", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
