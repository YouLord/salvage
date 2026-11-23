"""Wwise .pck (AKPK) / .bnk (BKHD) → .wem: разбор и честные статусы кодека."""
from __future__ import annotations

import hashlib
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from salvage.plugins.generic import wwise

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
        self.assertEqual([c[0] for c in bnk.chunks], ["BKHD", "DIDX", "DATA"])
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
