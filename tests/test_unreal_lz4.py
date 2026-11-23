"""Unreal .pak: LZ4-блоки (v8), zlib-контроль, честный отказ для Oodle."""
from __future__ import annotations

import hashlib
import json
import struct
import unittest
from pathlib import Path

from salvage.plugins.generic import unreal_pak

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


def _have_lz4() -> bool:
    try:
        import lz4.block  # noqa: F401
        return True
    except Exception:
        return False


class TestUnrealLz4(unittest.TestCase):
    """LZ4-блоки в .pak (v8) + честные статусы для Oodle."""

    def test_lz4_blocks_byte_exact(self) -> None:
        from salvage.plugins.generic import unreal_pak
        fix = FIX / "ue_lz4"
        if not (fix / "pakchunk0-WindowsNoEditor.pak").is_file():
            import importlib
            import sys
            sys.path.insert(0, str(HERE))
            importlib.import_module("make_fixture_unreal_lz4").build(fix)
        expected = json.loads((fix / "expected_lz4.json").read_text("utf-8"))
        pak = unreal_pak.read_pak(fix / "pakchunk0-WindowsNoEditor.pak")
        self.assertEqual(pak.version, 8)
        self.assertEqual(pak.compression_names[:4], ["None", "Zlib", "LZ4", "Oodle"])
        lz4_entries = 0
        for e in pak.entries:
            data, status = unreal_pak.read_entry_data(pak, e)
            self.assertEqual(status, "ok", f"{e.name}: {status}")
            self.assertEqual(hashlib.sha256(data).hexdigest(),
                             expected["files"][e.name]["sha256"], e.name)
            if e.compression == "lz4":
                lz4_entries += 1
        if expected["lz4_available"]:
            self.assertGreaterEqual(lz4_entries, 2, "LZ4-ветка не проверена")

    def test_oodle_is_honest_not_silent(self) -> None:
        """Неизвестный метод сжатия → статус unsupported, а не «мусор под видом данных»."""
        from salvage.plugins.generic import unreal_pak
        e = unreal_pak.PakEntry(name="x", offset=0, size=10, uncompressed=10,
                                method=3, compression_name="Oodle", header_size=4)
        pak = unreal_pak.PakFile(path=FIX / "ue_lz4" / "pakchunk0-WindowsNoEditor.pak",
                                 version=8, mount_point="", entries=[e],
                                 encrypted_index=False, compression_names=[], footer_offset=0)
        data, status = unreal_pak.read_entry_data(pak, e)
        self.assertIsNone(data)
        self.assertEqual(status, "unsupported:oodle")


class TestUnrealLz4MissingModule(unittest.TestCase):
    """Без python-lz4 модуль не имеет права выдавать «похожие байты».

    Статус обязан быть unsupported:lz4-python-missing, данные — None.
    """

    def test_missing_lz4_is_honest_status(self) -> None:
        from unittest import mock
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name.startswith("lz4"):
                raise ImportError("lz4 отключён в тесте")
            return real_import(name, *args, **kwargs)

        fix = FIX / "ue_lz4"
        expected = json.loads((fix / "expected_lz4.json").read_text("utf-8"))
        if not expected["lz4_available"]:
            self.skipTest("фикстура собрана без lz4 — нечего проверять")
        pak = unreal_pak.read_pak(fix / "pakchunk0-WindowsNoEditor.pak")
        lz4_entry = next(e for e in pak.entries if e.compression == "lz4")
        with mock.patch("builtins.__import__", side_effect=fake_import):
            data, status = unreal_pak.read_entry_data(pak, lz4_entry)
        self.assertIsNone(data, "без декодера данные подменяться не должны")
        self.assertEqual(status, "unsupported:lz4-python-missing")


if __name__ == "__main__":
    unittest.main(verbosity=2)
