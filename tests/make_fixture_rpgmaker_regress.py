"""Тонкая обёртка: регресс-фикстуры RPG Maker (см. fixtures_regress)."""
from __future__ import annotations

from pathlib import Path

import fixtures_regress as _reg


def build(root: Path) -> list[Path]:
    return [_reg.build_rm_nokey(root / "regress" / "rm" / "regress_nokey"),
            _reg.build_rm_v3_wrap(root / "regress" / "rm" / "regress_v3_wrap")]


BUG_CASE = {"regress_nokey": _reg.BUG_RM_NOKEY,
            "regress_v3_wrap": _reg.BUG_RM_V3_WRAP}
