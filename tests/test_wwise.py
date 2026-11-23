"""Wwise .pck (AKPK) / .bnk (BKHD) → .wem: разбор и честные статусы кодека."""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from salvage.core import wwise

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


class TestWwise(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="salvage-wwise-"))

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_pck_index_byte_exact(self) -> None:
        expected = json.loads((FIX / "wwise" / "expected.json").read_text("utf-8"))
        pck = wwise.read_pck(FIX / "wwise" / "Audio.pck")
        self.assertEqual(pck.version, 1)
        self.assertEqual(len(pck.entries), 2)
        for e in pck.entries:
            raw = wwise.read_wem_bytes(pck.path, e)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             expected["pck"]["entries"][str(e.wem_id)]["sha256"],
                             f"wem {e.wem_id}")

    def test_bnk_index_byte_exact(self) -> None:
        expected = json.loads((FIX / "wwise" / "expected.json").read_text("utf-8"))
        bnk = wwise.read_bnk(FIX / "wwise" / "SFX.bnk")
        self.assertEqual(bnk.version, 134)
        self.assertEqual([c[0] for c in bnk.chunks], ["BKHD", "DIDX", "DATA", "HIRC"])
        for e in bnk.entries:
            raw = wwise.read_wem_bytes(bnk.path, e)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),
                             expected["bnk"]["entries"][str(e.wem_id)]["sha256"])

    def test_wem_status_is_honest(self) -> None:
        """Wwise-обёртка «OggS» — не стандартный Ogg: статус не должен быть ogg."""
        expected = json.loads((FIX / "wwise" / "expected.json").read_text("utf-8"))
        pck = wwise.read_pck(FIX / "wwise" / "Audio.pck")
        bnk = wwise.read_bnk(FIX / "wwise" / "SFX.bnk")
        for e in pck.entries:
            status = wwise.wem_status(wwise.read_wem_bytes(pck.path, e))
            self.assertEqual(status, expected["statuses"][str(e.wem_id)])
            self.assertNotEqual(wwise.wem_extension(wwise.read_wem_bytes(pck.path, e)),
                                "ogg", "нельзя маскировать Wwise-поток под .ogg")
        for e in bnk.entries:
            status = wwise.wem_status(wwise.read_wem_bytes(bnk.path, e))
            self.assertEqual(status, expected["statuses"][str(e.wem_id)])

    def test_generic_plugin_extracts_wems(self) -> None:
        from salvage.core.plugin_base import EngineContext
        from salvage.core.registry import build_registry
        plugin = build_registry()["generic"]
        ds = plugin.scan(FIX / "wwise", EngineContext(deep=True, log=lambda m: None))
        self.assertEqual(ds.meta["wwise_wems"]["count"], 3)
        out = self.tmp / "wwise"
        summary = plugin.extract(ds, out, EngineContext(log=lambda m: None))
        wems = list((out / "wwise").rglob("wem_*"))
        self.assertEqual(len(wems), 3)
        self.assertGreaterEqual(summary["extracted"], 3)
        self.assertTrue(ds.meta["wwise_wem_status"])


class TestWwisevsGodot(unittest.TestCase):
    """Godot-плагин не должен присваивать Wwise .pck (magic AKPK)."""

    def test_godot_detect_rejects_akpk(self) -> None:
        from salvage.plugins.godot.plugin import GodotPlugin
        root = FIX / "wwise"
        plugin = GodotPlugin()
        score, evidence = plugin.detect(root)
        self.assertLess(score, 0.35, f"Godot заявил Wwise-пакеты: {evidence}")

    def test_godot_scan_marks_foreign(self) -> None:
        from salvage.core.plugin_base import EngineContext
        from salvage.plugins.godot.plugin import GodotPlugin
        plugin = GodotPlugin()
        ds = plugin.scan(FIX / "wwise", EngineContext())
        asset = next(a for a in ds.assets if a.path.endswith("Audio.pck"))
        self.assertEqual(asset.extra.get("foreign_pck"), "wwise")
        self.assertNotIn("pck_unrecognized", asset.extra)
        self.assertTrue(any(f.code == "wwise_pck_in_godot" for f in ds.findings))


class TestHircAndBoundaries(unittest.TestCase):
    """HIRC-инвентарь и честные ошибки вместо «правдоподобных» записей."""

    def test_hirc_inventory(self) -> None:
        bnk = wwise.read_bnk(FIX / "wwise" / "SFX.bnk")
        self.assertEqual(bnk.version, 134)
        self.assertEqual(bnk.bank_id, 0x0BADBEEF)
        self.assertEqual(bnk.hirc_total, 3)
        self.assertEqual(bnk.hirc_types, {2: 2, 4: 1})
        self.assertEqual(bnk.hirc_error, "")

    def test_bank_id_and_language(self) -> None:
        bnk = wwise.read_bnk(FIX / "wwise" / "SFX.bnk")
        self.assertEqual(bnk.language, 0)

    def test_truncated_chunk_is_error(self) -> None:
        raw = (FIX / "wwise" / "SFX.bnk").read_bytes()
        broken = raw[:-40]                      # отрезали хвост DATA/HIRC
        with self.assertRaises(wwise.WwiseError):
            wwise.read_bnk(_write_tmp(self, "cut.bnk", broken))

    def test_didx_without_data_is_error(self) -> None:
        bkhd = b"BKHD" + struct.pack("<I", 8) + struct.pack("<II", 134, 7)
        didx = b"DIDX" + struct.pack("<I", 12) + struct.pack("<III", 1, 0, 4)
        with self.assertRaises(wwise.WwiseError):
            wwise.read_bnk(_write_tmp(self, "nodata.bnk", bkhd + didx))

    def test_media_out_of_bounds_is_error(self) -> None:
        bkhd = b"BKHD" + struct.pack("<I", 8) + struct.pack("<II", 134, 7)
        didx = b"DIDX" + struct.pack("<I", 12) + struct.pack("<III", 1, 0, 999)
        data = b"DATA" + struct.pack("<I", 4) + b"abcd"
        with self.assertRaises(wwise.WwiseError):
            wwise.read_bnk(_write_tmp(self, "oob.bnk", bkhd + didx + data))

    def test_unknown_pck_is_error(self) -> None:
        with self.assertRaises(wwise.WwiseError):
            wwise.read_pck(_write_tmp(self, "not.pck", b"XXXX" + bytes(64)))

    def test_pck_header_size_out_of_file(self) -> None:
        bad = b"AKPK" + struct.pack("<IIIII", 10 ** 6, 0, 0, 0, 0) + bytes(16)
        with self.assertRaises(wwise.WwiseError):
            wwise.read_pck(_write_tmp(self, "bad.pck", bad))


class TestWemStatuses(unittest.TestCase):
    def test_statuses_from_fixture(self) -> None:
        expected = json.loads((FIX / "wwise" / "expected.json").read_text("utf-8"))
        for name in ("Audio.pck", "SFX.bnk"):
            container = FIX / "wwise" / name
            reader = wwise.read_pck if name.endswith(".pck") else wwise.read_bnk
            obj = reader(container)
            for e in obj.entries:
                payload = wwise.read_wem_bytes(container, e)
                status = wwise.wem_status(payload)
                self.assertEqual(status, expected["statuses"][str(e.wem_id)],
                                 f"{name}:{e.wem_id}")

    def test_wem_export_is_byte_exact(self) -> None:
        expected = json.loads((FIX / "wwise" / "expected.json").read_text("utf-8"))
        bnk = wwise.read_bnk(FIX / "wwise" / "SFX.bnk")
        entry = bnk.entries[0]
        payload = wwise.read_wem_bytes(FIX / "wwise" / "SFX.bnk", entry)
        self.assertEqual(hashlib.sha256(payload).hexdigest(),
                         expected["pck"]["entries"][str(entry.wem_id)]["sha256"]
                         if str(entry.wem_id) in expected["pck"]["entries"]
                         else expected["bnk"]["entries"][str(entry.wem_id)]["sha256"])
        self.assertEqual(payload[:4], b"RIFF", "PCM-wem должен быть RIFF")


def _write_tmp(case: unittest.TestCase, name: str, data: bytes) -> Path:
    import tempfile
    d = getattr(case, "_tmpdir", None)
    if d is None:
        d = Path(tempfile.mkdtemp(prefix="wwise-"))
        case._tmpdir = d
    path = d / name
    path.write_bytes(data)
    return path


if __name__ == "__main__":
    unittest.main(verbosity=2)
