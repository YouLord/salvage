"""Сквозной тест FMOD Vorbis: реальный tone.ogg → FSB5 → обратно в Ogg.

Доказательство «открывается в плеерах» строится без внешних утилит:
  * свой парсер страниц проверяет CRC/sequence/serial/BOS/EOS/granule;
  * если есть soundfile — декодируем и сверяем PCM с исходным tone.ogg.

tone.ogg лежит в tests/assets/ и коммитится: тесты/fixtures исключены из git,
а входной ассет — нет (иначе доказательство нечем воспроизвести).
"""
from __future__ import annotations

import io
import unittest
from pathlib import Path

from salvage.core import ogg
from salvage.plugins.generic import fmod_fsb

HERE = Path(__file__).resolve().parent
TONE = HERE / "assets" / "tone.ogg"


def _have_soundfile() -> bool:
    try:
        import soundfile  # noqa: F401
        return True
    except Exception:
        return False


class TestToneRoundtrip(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not TONE.is_file():
            raise unittest.SkipTest("нет tests/assets/tone.ogg (python tests/make_asset_tone.py)")

    def _rebuild(self):
        import importlib
        import sys
        import tempfile

        sys.path.insert(0, str(HERE))
        mod = importlib.import_module("make_fixture_fmod_vorbis")
        raw = TONE.read_bytes()
        pages = ogg.parse_pages(raw)
        total = pages[-1].granule
        bank = mod.pack_ogg_into_fsb(raw, samples=total)
        path = Path(tempfile.mkdtemp(prefix="tone-")) / "tone.bank"
        path.write_bytes(bank)
        fsb = fmod_fsb.read_fsb(path)
        sample = fsb.samples[0]
        payload = fmod_fsb.sample_payload(fsb, sample)
        return sample, payload, total

    def test_structure_is_valid_ogg(self) -> None:
        sample, payload, total = self._rebuild()
        self.assertEqual(sample.frequency, 22050)
        self.assertEqual(sample.samples, total)
        result = fmod_fsb.build_ogg_verified(sample, payload)
        self.assertEqual(result["status"], "ok", result)
        data = result["data"]
        self.assertIsNotNone(data)

        pages = ogg.parse_pages(data)
        self.assertGreaterEqual(len(pages), 3)
        self.assertEqual(pages[0].header_type & 0x02, 0x02, "нет BOS")
        self.assertEqual(pages[-1].header_type & 0x04, 0x04, "нет EOS")
        self.assertEqual([p.sequence for p in pages], list(range(len(pages))))
        self.assertEqual(len({p.serial for p in pages}), 1, "serial разъехался")
        self.assertEqual(pages[-1].granule, total, "итоговый granule не равен сэмплам")
        # промежуточные granule: -1 (легально по спецификации) или монотонные
        for p in pages[2:-1]:
            self.assertIn(p.granule, (-1,), f"промежуточный granule {p.granule}")
        info = ogg.verify_stream(data)
        self.assertEqual(info["granule"], total)
        # заголовки Vorbis на месте и правильного типа
        self.assertTrue(pages[0].packets[0].startswith(b"\x01vorbis"))
        self.assertTrue(pages[1].packets[0].startswith(b"\x03vorbis"))
        self.assertTrue(pages[1].packets[1].startswith(b"\x05vorbis"))

    @unittest.skipUnless(_have_soundfile(), "нет soundfile — сравнить PCM нечем")
    def test_decoded_pcm_matches_source(self) -> None:
        import numpy as np
        import soundfile as sf

        sample, payload, total = self._rebuild()
        result = fmod_fsb.build_ogg_verified(sample, payload)
        self.assertIsNotNone(result["data"])
        original, rate0 = sf.read(str(TONE), dtype="float32")
        restored, rate1 = sf.read(io.BytesIO(result["data"]), dtype="float32")
        self.assertEqual(rate0, rate1)
        self.assertEqual(len(original), len(restored), "длина PCM разошлась")
        self.assertEqual(len(restored), total)
        corr = float(np.corrcoef(original, restored)[0, 1])
        self.assertGreater(corr, 0.999, f"звук не совпал: corr={corr:.4f}")
        self.assertLess(float(np.abs(original - restored).max()), 1e-3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
