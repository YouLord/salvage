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
        self.assertEqual(status, "compression:oodle")


class TestMethodConventions(unittest.TestCase):
    """Три конвенции поля method — все зафиксированы тестами."""

    def test_v8_one_based_table(self) -> None:
        # основная конвенция: 5 слотов, нулевой «пустой», method=1 → names[0]
        names = ["Zlib", "LZ4", "Oodle", "None", ""]
        self.assertEqual(unreal_pak.method_name(0, names, 8), "none")
        self.assertEqual(unreal_pak.method_name(1, names, 8), "zlib")
        self.assertEqual(unreal_pak.method_name(2, names, 8), "lz4")
        self.assertEqual(unreal_pak.method_name(3, names, 8), "oodle")
        # за пределами таблицы не угадываем
        self.assertEqual(unreal_pak.method_name(7, names, 8), "")

    def test_v8_zero_based_table_with_none_slot(self) -> None:
        # таблица с явным None в нулевом слоте → индексация с нуля
        names = ["None", "Zlib", "LZ4", "Oodle", ""]
        self.assertEqual(unreal_pak.method_name(0, names, 8), "none")
        self.assertEqual(unreal_pak.method_name(1, names, 8), "zlib")
        self.assertEqual(unreal_pak.method_name(2, names, 8), "lz4")
        self.assertEqual(unreal_pak.method_name(3, names, 8), "oodle")

    def test_shift_error_would_be_caught(self) -> None:
        """Если перепутать конвенции, method=1 станет LZ4 вместо Zlib — тест падает."""
        one_based = ["Zlib", "LZ4", "Oodle", "None", ""]
        zero_based = ["None", "Zlib", "LZ4", "Oodle", ""]
        self.assertNotEqual(unreal_pak.method_name(1, one_based, 8),
                            unreal_pak.method_name(2, zero_based, 8))

    def test_legacy_flags_v1_v7(self) -> None:
        self.assertEqual(unreal_pak.method_name(0, [], 3), "none")
        self.assertEqual(unreal_pak.method_name(0x01, [], 3), "zlib")
        self.assertEqual(unreal_pak.method_name(0x02, [], 3), "gzip")
        self.assertEqual(unreal_pak.method_name(0x04, [], 3), "custom")
        self.assertEqual(unreal_pak.method_name(0x10, [], 3), "bias-memory")
        self.assertEqual(unreal_pak.method_name(0x20, [], 3), "bias-speed")

    def test_unknown_method_is_not_guessed(self) -> None:
        """Без таблицы имён номер 0x10 (LZ4 в legacy) не превращается в LZ4."""
        self.assertEqual(unreal_pak.method_name(0x10, [], 8), "")

    def test_fixture_uses_index_convention(self) -> None:
        fix = FIX / "ue_lz4"
        pak = unreal_pak.read_pak(fix / "pakchunk0-WindowsNoEditor.pak")
        self.assertEqual(pak.compression_names[:4], ["None", "Zlib", "LZ4", "Oodle"])
        by_name = {e.name: e for e in pak.entries}
        crate = by_name["Content/Meshes/SM_Crate.uasset"]
        self.assertEqual((crate.method, crate.compression), (2, "lz4"))
        hit = by_name["Content/Audio/S_Hit.uasset"]
        self.assertEqual((hit.method, hit.compression), (1, "zlib"))


class TestNoNoneTable(unittest.TestCase):
    """pak v8 с таблицей ["Zlib","LZ4","Oodle"] и записями zlib/lz4/oodle."""

    @classmethod
    def setUpClass(cls) -> None:
        fix = FIX / "ue_lz4"
        if not (fix / "pak_no_none.pak").is_file():
            import importlib
            import sys
            sys.path.insert(0, str(HERE))
            importlib.import_module("make_fixture_unreal_lz4").build(fix)
        cls.pak = unreal_pak.read_pak(fix / "pak_no_none.pak")

    def test_names_and_methods(self) -> None:
        self.assertEqual(self.pak.compression_names[:3], ["Zlib", "LZ4", "Oodle"])
        got = {e.name: (e.method, e.compression) for e in self.pak.entries}
        self.assertEqual(got["Content/A/plain.ubulk"], (0, "none"))
        self.assertEqual(got["Content/B/lz4.ubulk"], (2, "lz4"))

    def test_lz4_byte_exact_without_none_slot(self) -> None:
        entry = next(e for e in self.pak.entries if e.name == "Content/B/lz4.ubulk")
        data, status = unreal_pak.read_entry_data(self.pak, entry)
        self.assertEqual(status, "ok")
        self.assertEqual(data, b"LZ4 payload " * 40)

    def test_oodle_is_skipped_honestly(self) -> None:
        entry = next(e for e in self.pak.entries if e.compression == "oodle")
        data, status = unreal_pak.read_entry_data(self.pak, entry)
        self.assertIsNone(data)
        self.assertEqual(status, "compression:oodle")


class TestUnrealLz4MissingModule(unittest.TestCase):
    """Паки с method=0x10 не должны давать мусор при отсутствии декодера.

    Чистый Python-декодер (salvage/core/lz4.py) обязателен, поэтому:
      • метод распознан по имени footer'а и данные распакованы → ok;
      • имя не распознано (нет таблицы имён) → честный compression:…, данные = None;
      • повреждённый блок → error:lz4:…, данные = None (никаких «похожих байтов»).
    """

    def _pak(self):
        fix = FIX / "ue_lz4"
        if not (fix / "pakchunk0-WindowsNoEditor.pak").is_file():
            import importlib
            import sys
            sys.path.insert(0, str(HERE))
            importlib.import_module("make_fixture_unreal_lz4").build(fix)
        return fix, unreal_pak.read_pak(fix / "pakchunk0-WindowsNoEditor.pak")

    def test_lz4_decodes_without_external_module(self) -> None:
        fix, pak = self._pak()
        expected = json.loads((fix / "expected_lz4.json").read_text("utf-8"))
        entry = next(e for e in pak.entries if e.compression == "lz4")
        data, status = unreal_pak.read_entry_data(pak, entry)
        self.assertEqual(status, "ok")
        self.assertEqual(hashlib.sha256(data).hexdigest(),
                         expected["files"][entry.name]["sha256"])

    def test_unknown_name_is_not_guessed(self) -> None:
        """Нет таблицы имён → метод не угадывается по номеру 0x10."""
        fix, pak = self._pak()
        entry = next(e for e in pak.entries if e.compression == "lz4")
        old = (entry.method, entry.compression_name, list(pak.compression_names))
        try:
            entry.method, entry.compression_name = 0x10, ""
            pak.compression_names = []
            data, status = unreal_pak.read_entry_data(pak, entry)
        finally:
            entry.method, entry.compression_name = old[0], old[1]
            pak.compression_names = old[2]
        self.assertIsNone(data)
        self.assertEqual(status, "compression:0x10")

    def test_truncated_lz4_block_is_error(self) -> None:
        fix, pak = self._pak()
        entry = next(e for e in pak.entries if e.compression == "lz4")
        with open(pak.path, "rb") as f:
            f.seek(entry.data_offset)
            chunk = bytearray(f.read(entry.size))
        chunk = chunk[: max(4, len(chunk) // 2)]          # рвём блок
        from pathlib import Path as _P
        broken = _P(self._tmpdir()) / "broken.pak"
        raw = bytearray(pak.path.read_bytes())
        raw[entry.data_offset:entry.data_offset + entry.size] = chunk + bytes(
            entry.size - len(chunk))
        broken.write_bytes(bytes(raw))
        broken_pak = unreal_pak.read_pak(broken)
        data, status = unreal_pak.read_entry_data(
            broken_pak, next(e for e in broken_pak.entries if e.compression == "lz4"))
        self.assertIsNone(data, "обрезанный блок не должен давать байты")
        self.assertTrue(status.startswith("error:lz4"), status)

    def _tmpdir(self) -> str:
        import tempfile
        d = getattr(self, "_dir", None)
        if d is None:
            d = tempfile.mkdtemp(prefix="lz4-broken-")
            self._dir = d
        return d


if __name__ == "__main__":
    unittest.main(verbosity=2)
