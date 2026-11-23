"""FMOD FSB5 Vorbis → валидный OggS (проверка внешним декодером) + Ogg-примитивы."""
from __future__ import annotations

import hashlib
import io
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from salvage.core import ogg
from salvage.plugins.generic import fmod_fsb

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


class TestFmodVorbis(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp(prefix="salvage-fmodv-"))
        cls.fix = FIX / "fmod_vorbis"
        if not (cls.fix / "VorbisMusic.bank").is_file():
            import importlib
            import sys
            sys.path.insert(0, str(HERE))
            mod = importlib.import_module("make_fixture_fmod_vorbis")
            mod.build(cls.fix)

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_fsb5_header_layout_v1(self) -> None:
        """FSB5 v1: базовый заголовок 0x3C, заголовок сэмпла — 64-битное поле."""
        bank = fmod_fsb.read_fsb(self.fix / "VorbisMusic.bank")
        self.assertEqual(len(bank.samples), 1)
        s = bank.samples[0]
        self.assertEqual(s.codec_name, "vorbis")
        self.assertEqual(s.frequency, 22050)
        self.assertIsNotNone(s.vorbis_setup)
        self.assertTrue(s.vorbis_setup.startswith(b"\x05vorbis"))
        expected = json.loads((self.fix / "expected_vorbis.json").read_text("utf-8"))
        self.assertEqual(s.samples, expected["samples"])
        self.assertGreater(s.data_size, 0)
        self.assertLessEqual(s.data_offset + s.data_size, (self.fix / "VorbisMusic.bank").stat().st_size)

    def test_vorbis_rebuild_matches_reference_pcm(self) -> None:
        """Собранный Ogg должен декодироваться в тот же звук, что и эталон."""
        try:
            import soundfile as sf
            import numpy as np
        except Exception:  # pragma: no cover
            self.skipTest("нет soundfile/numpy — проверка звучания недоступна")
        bank = fmod_fsb.read_fsb(self.fix / "VorbisMusic.bank")
        s = bank.samples[0]
        payload = fmod_fsb.sample_payload(bank, s)
        result = fmod_fsb.build_ogg_verified(s, payload)
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["verified"])
        info = ogg.verify_stream(result["data"])
        self.assertEqual(info["granule"], s.samples)
        got, rate = sf.read(io.BytesIO(result["data"]), dtype="int16")
        ref, ref_rate = sf.read(str(self.fix / "reference.ogg"), dtype="int16")
        self.assertEqual(rate, ref_rate)
        self.assertEqual(len(got), len(ref))
        n = min(len(got), len(ref))
        corr = float(np.corrcoef(got[:n], ref[:n])[0, 1])
        self.assertGreater(corr, 0.9999, f"звук не совпал (corr={corr})")


class TestOggPrimitives(unittest.TestCase):
    def test_crc_roundtrip(self) -> None:
        page = ogg.build_page([b"hello"], serial=5, sequence=0, granule=7, header_type=0x02)
        parsed = ogg.parse_pages(page)
        self.assertEqual(parsed[0].segments, [b"hello"])
        self.assertEqual(parsed[0].granule, 7)

    def test_crc_detects_corruption(self) -> None:
        page = bytearray(ogg.build_page([b"payload"], serial=1, sequence=0))
        page[-1] ^= 0xFF
        with self.assertRaises(ogg.OggError):
            ogg.parse_pages(bytes(page))

    def test_lacing_255(self) -> None:
        packet = b"x" * 510   # ровно 2×255 => lacing 255,255,0
        page = ogg.build_page([packet], serial=1, sequence=0)
        parsed = ogg.parse_pages(page)
        self.assertEqual(parsed[0].segments, [packet])

    def test_verify_rejects_plain_junk(self) -> None:
        with self.assertRaises(ogg.OggError):
            ogg.verify_stream(b"OggS\x00salvage-fsb5-raw\x00not really an ogg")


class TestVorbisDataStrictness(unittest.TestCase):
    """Битая VORBISDATA — честная ошибка, а не «сырой контейнер как .ogg»."""

    def _sample(self, setup: bytes):
        from salvage.plugins.generic.fmod_fsb import FsbSample
        return FsbSample(index=0, name="x", codec=15, channels=1, frequency=22050,
                         samples=1000, data_offset=0, data_size=0,
                         vorbis_setup=setup)

    def test_missing_chunk(self) -> None:
        from salvage.plugins.generic import fmod_fsb
        res = fmod_fsb.build_ogg_verified(self._sample(b""), b"")
        self.assertIsNone(res["data"])
        self.assertEqual(res["status"], "headers-unrecoverable")
        self.assertIn("VORBISDATA", res.get("reason", ""))

    def test_wrong_magic_in_setup(self) -> None:
        from salvage.plugins.generic import fmod_fsb
        res = fmod_fsb.build_ogg_verified(self._sample(b"\x09vorbisgarbage"), b"x")
        self.assertIsNone(res["data"])
        self.assertEqual(res["status"], "headers-unrecoverable")
        self.assertIn("0x05", res.get("reason", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
