#!/usr/bin/env python3
"""Сборка синтетического тестового стенда.

Тонкая обёртка: каждый стенд живёт в своём модуле ``make_fixture_<engine>.py``
(контракт — ``fixture_base.Fixture``), чтобы фикстуры пересобирались по одной и
на каждый баг можно было добавить минимальный регресс-кейс.

    python tests/make_fixtures.py                 # все стенды
    python tests/make_fixtures.py gm renpy        # только выбранные
    python tests/make_fixtures.py gm --bug        # стенд с регресс-кейсом
"""
from __future__ import annotations

import importlib
import random
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent / "fixtures"

MODULES = {
    "unity": "make_fixture_unity",
    "godot": "make_fixture_godot",
    "gm": "make_fixture_gamemaker",
    "rm_mv": "make_fixture_rpgmaker_mv",
    "rm_xp": "make_fixture_rpgmaker_xp",
    "renpy": "make_fixture_renpy",
    "ue": "make_fixture_unreal",
    "fmod": "make_fixture_fmod",
}


def build_one(alias: str, *, with_bug: bool = False, base: Path | None = None) -> Path:
    mod = importlib.import_module(MODULES[alias])
    root = Path(base or BASE) / alias
    return mod.build(root, with_bug=with_bug)


def main(argv: list[str] | None = None) -> None:
    argv = list(argv if argv is not None else sys.argv[1:])
    with_bug = "--bug" in argv
    argv = [a for a in argv if a != "--bug"]
    names = argv or list(MODULES)
    random.seed(42)
    BASE.mkdir(parents=True, exist_ok=True)
    for alias in names:
        if alias not in MODULES:
            raise SystemExit(f"неизвестный стенд {alias}; есть: {', '.join(MODULES)}")
        build_one(alias, with_bug=with_bug)
        n = sum(1 for p in (BASE / alias).rglob("*") if p.is_file())
        print(f"  {alias:<8} файлов: {n}" + ("  (с регресс-кейсом)" if with_bug else ""))
    print(f"Стенд собран: {BASE}")


if __name__ == "__main__":
    main()
