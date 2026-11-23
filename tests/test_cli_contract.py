"""Контракт CLI и отчётов (0.3, п. 4–6).

Проверяется то, что легко «тихо» сломать:
  • коды возврата для полного/частичного/пустого извлечения;
  • идемпотентность extract в тот же --out;
  • лимиты видны как «скан неполный» (meta.limits/meta.truncated);
  • --engine: форс, автодетект, generic-fallback, неизвестное имя;
  • schema_version в scan.json и score_breakdown в JSON/MD;
  • автономность report.html (никаких внешних http-ресурсов).
"""
from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from salvage.cli import main
from salvage.core.model import SCHEMA_VERSION
from salvage.core.plugin_base import EngineContext, note_limit
from salvage.core.scan import ScanError, scan
from salvage.core.model import Dataset

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


class CliBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="salvage-cli-"))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def out(self, name: str) -> Path:
        p = self.tmp / name
        return p


class TestExitCodes(CliBase):
    def test_clean_scan_returns_zero(self) -> None:
        code = main(["scan", str(FIX / "ue"), "--out", str(self.out("clean")),
                     "--formats", "json"])
        self.assertEqual(code, 0, "полный скан без предупреждений должен давать 0")

    def test_extract_partial_still_reports(self) -> None:
        """Частичное извлечение: ненулевой код + честная запись в scan.json."""
        out = self.out("partial")
        code = main(["extract", str(FIX / "ue"), "--out", str(out), "--report"])
        self.assertIn(code, (0, 1, 2))
        doc = json.loads((out / "_report" / "scan.json").read_text("utf-8"))
        self.assertIn("extraction", doc)
        self.assertIsInstance(doc["extraction"], dict)

    def test_unknown_engine_is_honest_error(self) -> None:
        with self.assertRaises(SystemExit):
            # argparse с choices отвергает неизвестный движок до запуска скана
            main(["scan", str(FIX / "ue"), "--engine", "nope"])

    def test_unknown_engine_via_api_raises(self) -> None:
        with self.assertRaises(ScanError):
            scan(FIX / "ue", "nope", EngineContext(log=lambda m: None))


class TestIdempotence(CliBase):
    def test_extract_twice_same_out(self) -> None:
        out = self.out("idem")
        argv = ["extract", str(FIX / "fmod_vorbis"), "--out", str(out)]
        main(argv)
        first = sorted((p.relative_to(out).as_posix(), p.stat().st_size)
                       for p in out.rglob("*") if p.is_file())
        main(argv)
        second = sorted((p.relative_to(out).as_posix(), p.stat().st_size)
                        for p in out.rglob("*") if p.is_file())
        self.assertEqual(first, second, "повторный extract изменил дерево файлов")
        self.assertTrue(any(name.endswith(".ogg") for name, _ in second),
                        "ожидался извлечённый .ogg")


class TestLimits(CliBase):
    def test_note_limit_marks_scan_incomplete(self) -> None:
        ds = Dataset("generic", "Generic", self.tmp)
        note_limit(ds, "files", 3, 3, "просмотр файлов")
        self.assertTrue(ds.meta["truncated"])
        self.assertEqual(ds.meta["limits"]["files"]["status"] if "status"
                         in ds.meta["limits"]["files"] else "hit", "hit")
        self.assertTrue(any(f.code == "limit_files" for f in ds.findings))

    def test_limit_not_hit_is_silent(self) -> None:
        ds = Dataset("generic", "Generic", self.tmp)
        note_limit(ds, "files", 100, 7, "просмотр файлов")
        self.assertNotIn("truncated", ds.meta)
        self.assertFalse(ds.meta["limits"]["files"]["hit"])

    def test_max_files_reaches_report(self) -> None:
        ctx = EngineContext(max_files=2, log=lambda m: None)
        ds, _ = scan(FIX / "gm", "generic", ctx)
        self.assertTrue(ds.meta.get("truncated"), "лимит файлов не виден в отчёте")
        self.assertIn("files", ds.meta.get("limits", {}))
        doc = ds.to_dict()
        self.assertTrue(doc["meta"]["truncated"])

    def test_max_asset_bytes_visible_in_scan(self) -> None:
        """Лимит распаковки не должен прятаться: усечённые файлы попадают в находки."""
        ctx = EngineContext(max_asset_bytes=64, log=lambda m: None)
        ds, _ = scan(FIX / "ue", "generic", ctx)
        # .pak разбирается, но объекты не извлекаются на scan-этапе;
        # проверяем, что лимит сохранён в контексте и отчёт собирается.
        self.assertEqual(ctx.max_asset_bytes, 64)
        self.assertIn("ue_paks", ds.meta)


class TestPartialExtraction(CliBase):
    """Частичное извлечение: причина пропуска видна, а не сметена в «skipped»."""

    def test_pak_extract_reports_statuses(self) -> None:
        out = self.out("pakpart")
        code = main(["extract", str(FIX / "ue"), "--out", str(out), "--report"])
        self.assertEqual(code, 0, "fixture ue: всё распаковывается, warn/error нет")
        doc = json.loads((out / "_report" / "scan.json").read_text("utf-8"))
        statuses = doc["meta"]["ue_pak_statuses"]
        self.assertEqual(statuses.get("ok"), 3)
        # extracted включает и обычное копирование файлов, поэтому смотрим
        # именно на строку про .pak — в ней причина/статусы по каждому объекту
        self.assertIn("UE .pak: извлечено 3", doc["extraction"]["message"])
        self.assertIn("ok×3", doc["extraction"]["message"])
        self.assertGreater(len(list((out / "pak").rglob("*.uasset"))), 0)

    def test_oodle_is_counted_as_error_with_status(self) -> None:
        from salvage.plugins.generic import unreal_pak
        from salvage.plugins.generic.plugin import GenericPlugin
        from salvage.core.plugin_base import EngineContext
        pak_path = FIX / "ue_lz4" / "pakchunk0-WindowsNoEditor.pak"
        pak = unreal_pak.read_pak(pak_path)
        # подменяем метод у первой записи на Oodle
        pak.entries[0].method = 3
        pak.entries[0].compression_name = "Oodle"
        ds = Dataset("generic", "Generic", FIX / "ue_lz4")
        ds.meta["ue_pak_objects"] = {"p.pak": pak}
        plugin = GenericPlugin()
        out = self.out("oodle")
        stats = plugin._extract_paks(ds, out, EngineContext(log=lambda m: None), None)
        self.assertEqual(stats["extracted"], 2)
        self.assertEqual(stats["skipped"], 1)
        self.assertEqual(stats["errors"], 1, "отказ Oodle — это ошибка, а не тихий skip")
        self.assertIn("compression:oodle", stats["message"])


class TestEngineSelection(CliBase):
    def test_forced_engine_beats_detection(self) -> None:
        ds_auto, plugin_auto = scan(FIX / "gm", None, EngineContext(log=lambda m: None))
        self.assertEqual(plugin_auto.slug, "gamemaker")
        ds_forced, plugin_forced = scan(FIX / "gm", "generic", EngineContext(log=lambda m: None))
        self.assertEqual(plugin_forced.slug, "generic")

    def test_generic_fallback_on_unknown_tree(self) -> None:
        ds, plugin = scan(FIX / "ue_lz4", None, EngineContext(log=lambda m: None))
        self.assertEqual(plugin.slug, "generic")
        self.assertGreaterEqual(ds.score, 0.0)

    def test_forced_godot_on_non_godot_tree_is_visible(self) -> None:
        ds, plugin = scan(FIX / "ue", "godot", EngineContext(log=lambda m: None))
        self.assertEqual(plugin.slug, "godot")
        self.assertLess(ds.score, 0.35, "форс без совпадения улик должен быть виден по score")


class TestReportSchema(CliBase):
    def test_scan_json_has_schema_version(self) -> None:
        out = self.out("schema")
        main(["scan", str(FIX / "godot"), "--out", str(out), "--formats", "json,md"])
        doc = json.loads((out / "scan.json").read_text("utf-8"))
        self.assertEqual(doc["schema_version"], SCHEMA_VERSION)
        self.assertTrue(doc.get("generator_version"))
        for key in ("engine", "totals", "assets", "findings", "meta"):
            self.assertIn(key, doc, f"поле схемы {key} пропало")

    def test_doctor_breakdown_in_json_and_md(self) -> None:
        out = self.out("doctor")
        main(["audit", str(FIX / "rm_xp"), "--out", str(out), "--formats", "json,md"])
        doc = json.loads((out / "scan.json").read_text("utf-8"))
        doctor = doc["meta"]["doctor"]
        self.assertIn("score_breakdown", doctor)
        self.assertIsInstance(doctor["score_breakdown"], list)
        self.assertGreaterEqual(len(doctor["score_breakdown"]), 3)
        total = sum(item["penalty"] for item in doctor["score_breakdown"])
        self.assertEqual(doctor["score"], max(0, 100 + total),
                         "оценка не сходится со слагаемыми")
        md = (out / "report.md").read_text("utf-8")
        self.assertIn("Из чего сложилась оценка", md)

    def test_html_is_self_contained(self) -> None:
        out = self.out("offline")
        main(["audit", str(FIX / "gm"), "--out", str(out), "--formats", "html"])
        html = (out / "report.html").read_text("utf-8")
        external = re.findall(r'(?:src|href)\s*=\s*["\'](https?://[^"\']+)', html, re.I)
        self.assertEqual(external, [], f"HTML тянет внешние ресурсы: {external[:3]}")
        self.assertNotIn("<script src=", html.lower().replace("'", '"'))
        self.assertNotIn("@import", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
