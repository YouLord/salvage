"""Чистый Python-декодер LZ4 block (salvage/core/lz4.py).

Проверки:
  * сверка с эталонным декодером lz4.block (skipUnless — зависимость опциональна);
  * перекрывающиеся match-и (offset < длины match) — легальный приём LZ4;
  * строгость: обрезка/порча/offset за границей → Lz4BlockError, не «мусор».
"""
from __future__ import annotations

import importlib.util
import os
import random
import unittest

from salvage.core import lz4

HAVE_REF = importlib.util.find_spec("lz4") is not None


def _corpus() -> list[bytes]:
    random.seed(1234)
    items = [
        b"",
        b"a",
        b"ab" * 3,
        b"X" * 32,                                  # длинный match с offset 1
        bytes(range(256)) * 40,
        b"UE4 pak block test " * 500,
        bytes(300),
    ]
    for i in range(30):
        n = random.randint(0, 3000)
        kind = i % 3
        if kind == 0:
            items.append(bytes(random.choice(b"ab\x00") for _ in range(n)))
        elif kind == 1:
            items.append(bytes(random.getrandbits(8) for _ in range(n)))
        else:
            items.append((b"pattern-%d-" % i * (n // 10 + 2))[:n])
    return items


class TestLz4Decoder(unittest.TestCase):
    @unittest.skipUnless(HAVE_REF, "нет lz4 — сверять не с чем")
    def test_matches_reference_decoder(self) -> None:
        import lz4.block as ref
        for blob in _corpus():
            compressed = ref.compress(blob, store_size=False)
            self.assertEqual(lz4.decompress_block(compressed, len(blob)), blob,
                             f"расхождение на {len(blob)} байтах")
            self.assertEqual(lz4.decompress_block(compressed), blob)

    def test_overlapping_match_is_legal(self) -> None:
        """offset=1 при match длиннее offset — легальный приём (RLE-повторы)."""
        # Поток из эталонного кодера для b"a"*19 + b"b": offset=1, match длиннее
        # offset — перекрывающаяся копия. Это же проверяет и референс.
        stream = bytes.fromhex("1a610100506161616162")
        self.assertEqual(lz4.decompress_block(stream), b"a" * 19 + b"b")
        if HAVE_REF:
            import lz4.block as ref
            self.assertEqual(lz4.decompress_block(stream, 20),
                             ref.decompress(stream, uncompressed_size=20))

    def test_truncated_block_raises(self) -> None:
        data = b"hello world " * 20
        with self.assertRaises(lz4.Lz4BlockError):
            lz4.decompress_block(b"\x10\x00", len(data))

    def test_bad_offset_raises(self) -> None:
        # token = 0 (нет literals), offset = 5, но ничего ещё не распаковано
        with self.assertRaises(lz4.Lz4BlockError):
            lz4.decompress_block(b"\x00\x05\x00\x00")

    def test_size_mismatch_raises(self) -> None:
        data = b"0123456789"
        if not HAVE_REF:
            self.skipTest("нужен эталонный компрессор")
        import lz4.block as ref
        compressed = ref.compress(data, store_size=False)
        with self.assertRaises(lz4.Lz4BlockError):
            lz4.decompress_block(compressed, len(data) + 5)

    def test_empty(self) -> None:
        self.assertEqual(lz4.decompress_block(b""), b"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
