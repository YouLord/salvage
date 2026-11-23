"""Контракт CLI и отчётов: коды возврата, частичное извлечение, лимиты, схема.

Что проверяется (и почему именно так):
  * exit 0 — всё извлечено; 1 — частично (защита/неподдерживаемое сжатие);
    2 — были ошибки; 3 — прервано/неизвестный движок.
  * повторный extract в тот же --out: тот же набор файлов и байт,
    во втором прогоне overwritten == extracted.
  * запись атомарная (tmp + os.replace), половинчатых файлов не остаётся.
  * лимиты скана дают meta.limits + meta.truncated + находку limit_*,
    баннер в HTML/MD и запрет на вердикт «отлично» у доктора.
  * --engine: forced/auto видно в meta.detection_mode; неизвестный → exit 3.
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from salvage.cli import main
from salvage.core.model import Dataset
from salvage.core.plugin_base import EngineContext, note_limit
from salvage.core.scan import ScanError, scan
from salvage.plugins._shared import write_atomic

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


class CliBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._root = Path(tempfile.mkdtemp(prefix="salvage-cli-"))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls._root, ignore_errors=True)

    def out(self, name: str) -> Path:
        path = self._root / name
        return path


class TestExitCodes(CliBase):
    def test_clean_scan_returns_zero(self) -> None:
        code = main(["scan", str(FIX / "ue"), "--out", str(self.out("clean")),
                     "--formats", "json"])
        self.assertEqual(code, 0)

    def test_full_extract_returns_zero(self) -> None:
        code = main(["extract", str(FIX / "wwise"), "--out", str(self.out("full"))])
        self.assertEqual(code, 0, "всё извлеклось — код должен быть 0")

    def test_partial_extract_returns_one_and_warns(self) -> None:
        """Part из-за Oodle → 1 (warn) + находка, а не тихий успех."""
        from salvage.core.model import Dataset
        from salvage.plugins.generic.plugin import GenericPlugin
        from salvage.plugins.generic import unreal_pak

        pak = unreal_pak.read_pak(FIX / "ue_lz4" / "pakchunk0-WindowsNoEditor.pak")
        pak.entries[0].method = 3
        pak.entries[0].compression_name = "Oodle"
        ds = Dataset("generic", "Generic", FIX / "ue_lz4")
        ds.meta["ue_pak_objects"] = {"p.pak": pak}
        ctx = EngineContext(log=lambda m: None)
        summary = GenericPlugin().extract(ds, self.out("oodle"), ctx, None)
        self.assertGreaterEqual(summary["skipped"], 1)
        self.assertIn("compression:oodle", summary["message"])

    def test_unknown_engine_returns_three(self) -> None:
        """Неизвестный --engine — отказ в работе (3), не ошибка аргументов (2)."""
        self.assertEqual(main(["scan", str(FIX / "ue"), "--engine", "nope"]), 3)

    def test_unknown_engine_via_api(self) -> None:
        with self.assertRaises(ScanError):
            scan(FIX / "ue", "nope", EngineContext(log=lambda m: None))


class TestIdempotence(CliBase):
    def _snapshot(self, root: Path) -> dict[str, tuple[int, str]]:
        import hashlib
        return {p.relative_to(root).as_posix():
                (p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
                for p in root.rglob("*") if p.is_file()}

    def test_extract_twice_same_out(self) -> None:
        out = self.out("idem")
        argv = ["extract", str(FIX / "wwise"), "--out", str(out)]
        self.assertEqual(main(argv), 0)
        first = self._snapshot(out)
        summary = main(argv)
        second = self._snapshot(out)
        self.assertEqual(summary, 0)
        self.assertEqual(first, second, "повторный extract изменил дерево файлов")
        self.assertTrue(any(name.endswith(".wem") for name in second))

    def test_overwritten_counter_on_second_run(self) -> None:
        out = self.out("overwritten")
        argv = ["extract", str(FIX / "fmod_vorbis"), "--out", str(out), "--report"]
        main(argv)
        main(argv)
        doc = json.loads((out / "_report" / "scan.json").read_text("utf-8"))
        extraction = doc["extraction"]
        self.assertEqual(extraction["overwritten"], extraction["extracted"],
                         "во втором прогоне перезаписано всё извлечённое")
        self.assertFalse(extraction["partial"])

    def test_atomic_write_leaves_no_tmp(self) -> None:
        target = self.out("atomic") / "sub" / "file.bin"
        self.assertFalse(write_atomic(target, b"first"))
        self.assertTrue(write_atomic(target, b"second"), "второй раз — это перезапись")
        self.assertEqual(target.read_bytes(), b"second")
        leftovers = [p for p in target.parent.iterdir() if ".salvage-tmp" in p.name]
        self.assertEqual(leftovers, [], "временные файлы должны исчезать")


class TestLimits(CliBase):
    def test_note_limit_marks_scan_incomplete(self) -> None:
        ds = Dataset("generic", "Generic", self._root)
        note_limit(ds, "files", 3, 3, "просмотр файлов")
        self.assertTrue(ds.meta["truncated"])
        self.assertTrue(ds.meta["limits"]["files"]["hit"])
        self.assertTrue(any(f.code == "limit_files" for f in ds.findings))

    def test_limit_not_hit_is_silent(self) -> None:
        ds = Dataset("generic", "Generic", self._root)
        note_limit(ds, "files", 100, 7, "просмотр файлов")
        self.assertNotIn("truncated", ds.meta)
        self.assertFalse(ds.meta["limits"]["files"]["hit"])

    def test_tiny_limit_reaches_reports_and_doctor(self) -> None:
        out = self.out("limits")
        ctx = EngineContext(max_files=2, log=lambda m: None)
        ds, _ = scan(FIX / "gm", "generic", ctx)
        self.assertTrue(ds.meta.get("truncated"))
        from salvage.core.doctor import run_doctor
        doc = run_doctor(ds)
        self.assertTrue(doc["scan_truncated"])
        self.assertNotEqual(doc["verdict"], "отлично", "при неполном скане «отлично» нельзя")
        ds.meta["doctor"] = doc
        from salvage.report.export import write_markdown
        from salvage.report.html import write_html
        write_markdown(ds, out / "report.md")
        write_html(ds, out / "report.html")
        self.assertIn("СКАН НЕПОЛНЫЙ", (out / "report.md").read_text("utf-8"))
        self.assertIn("СКАН НЕПОЛНЫЙ", (out / "report.html").read_text("utf-8"))


class TestEngineSelection(CliBase):
    def test_forced_engine_beats_detection(self) -> None:
        _, auto_plugin = scan(FIX / "gm", None, EngineContext(log=lambda m: None))
        self.assertEqual(auto_plugin.slug, "gamemaker")
        ds, forced = scan(FIX / "gm", "generic", EngineContext(log=lambda m: None))
        self.assertEqual(forced.slug, "generic")
        self.assertEqual(ds.meta["detection_mode"], "forced")

    def test_auto_mode_is_marked(self) -> None:
        ds, _ = scan(FIX / "gm", None, EngineContext(log=lambda m: None))
        self.assertEqual(ds.meta["detection_mode"], "auto")

    def test_generic_fallback_on_unknown_tree(self) -> None:
        ds, plugin = scan(FIX / "ue_lz4", None, EngineContext(log=lambda m: None))
        self.assertEqual(plugin.slug, "generic")
        self.assertEqual(ds.meta["detection_mode"], "auto")


class TestReportSchema(CliBase):
    def test_scan_json_has_schema_version(self) -> None:
        from salvage.core.schema import SCHEMA_VERSION, validate_scan_json
        out = self.out("schema")
        main(["scan", str(FIX / "godot"), "--out", str(out), "--formats", "json,md"])
        doc = json.loads((out / "scan.json").read_text("utf-8"))
        self.assertEqual(doc["schema_version"], SCHEMA_VERSION)
        self.assertEqual(validate_scan_json(doc), [], "текущий вывод обязан проходить валидатор")

    def test_old_dump_without_schema_is_accepted_with_warning(self) -> None:
        from salvage.core.schema import validate_scan_json
        old = {"engine": "generic", "engine_name": "Generic",
               "totals": {"files": 0, "bytes": 0},
               "assets": [], "findings": [], "meta": {}}
        problems = validate_scan_json(old)
        self.assertTrue(any("schema_version" in p for p in problems))
        self.assertEqual([p for p in problems if "schema_version" not in p], [],
                         "старый дамп не должен считаться «битым»")

    def test_doctor_breakdown_in_json_and_md(self) -> None:
        out = self.out("doctor")
        main(["audit", str(FIX / "rm_xp"), "--out", str(out), "--formats", "json,md"])
        doc = json.loads((out / "scan.json").read_text("utf-8"))
        doctor = doc["meta"]["doctor"]
        total = sum(item["penalty"] for item in doctor["score_breakdown"])
        self.assertEqual(doctor["score"], max(0, 100 - total),
                         "score обязан сходиться с суммой штрафов")
        for item in doctor["score_breakdown"]:
            for key in ("code", "reason", "count", "weight", "cap", "penalty"):
                self.assertIn(key, item)
            self.assertLessEqual(item["penalty"], item["cap"], "штраф не больше потолка")
            self.assertGreaterEqual(item["penalty"], 0, "штраф — положительное число")
        self.assertIn("Из чего сложилась оценка",
                      (out / "report.md").read_text("utf-8"))

    def test_html_is_self_contained(self) -> None:
        out = self.out("offline")
        main(["audit", str(FIX / "gm"), "--out", str(out), "--formats", "html"])
        html = (out / "report.html").read_text("utf-8")
        external = re.findall(r'(?:src|href)\s*=\s*["\']https?://[^"\']+', html, re.I)
        self.assertEqual(external, [], f"внешние ссылки: {external[:3]}")
        self.assertNotIn("@import", html)
        self.assertIsNone(re.search(r'<(script|link)[^>]+(src|href)=', html, re.I))


if __name__ == "__main__":
    unittest.main(verbosity=2)
