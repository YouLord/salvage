"""Тонкая обёртка: регресс-фикстуры GameMaker (см. fixtures_regress)."""
from __future__ import annotations

from pathlib import Path

import fixtures_regress as _reg


def build(root: Path) -> list[Path]:
    return [_reg.build_gm_strg_abs(root / "regress" / "gm" / "regress_abs_strings"),
            _reg.build_gm_tpag(root / "regress" / "gm" / "regress_tpag_align")]


BUG_CASE = {"regress_abs_strings": _reg.BUG_GM_ABS_STRINGS,
            "regress_tpag_align": _reg.BUG_GM_TPAG}
