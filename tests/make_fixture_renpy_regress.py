"""Тонкая обёртка: регресс-фикстуры Ren'Py (см. fixtures_regress)."""
from __future__ import annotations

from pathlib import Path

import fixtures_regress as _reg


def build(root: Path) -> list[Path]:
    return [_reg.build_renpy_old_rpyc(root / "regress" / "renpy" / "regress_old_rpyc"),
            _reg.build_renpy_rpa32(root / "regress" / "renpy" / "regress_slot2_only")]


BUG_CASE = {"regress_old_rpyc": _reg.BUG_RENPY_OLD_RPYC,
            "regress_slot2_only": _reg.BUG_RENPY_SLOT2}
