"""Реестр плагинов-движков.

Добавить новый движок = создать пакет salvage/plugins/<slug>/plugin.py
с классом EnginePlugin и импортировать его в build_registry().
Названия модулей фиксированы, чтобы ядро оставалось зависимым только от
протокола EnginePlugin (см. core/plugin_base.py), а не от конкретики.
"""
from __future__ import annotations

from .model import Dataset
from .plugin_base import EngineContext, EnginePlugin


def build_registry() -> dict[str, EnginePlugin]:
    registry: dict[str, EnginePlugin] = {}

    from ..plugins.unity.plugin import UnityPlugin
    from ..plugins.godot.plugin import GodotPlugin
    from ..plugins.gamemaker.plugin import GameMakerPlugin
    from ..plugins.rpgmaker.plugin import RPGMakerPlugin
    from ..plugins.renpy.plugin import RenPyPlugin
    from ..plugins.generic.plugin import GenericPlugin

    for cls in (UnityPlugin, GodotPlugin, GameMakerPlugin,
                RPGMakerPlugin, RenPyPlugin, GenericPlugin):
        plugin = cls()
        registry[plugin.slug] = plugin
    return registry


def detect_all(root, registry: dict[str, EnginePlugin] | None = None
               ) -> list[tuple[EnginePlugin, float, list[str]]]:
    """Все движки с ненулевым score, по убыванию уверенности."""
    registry = registry or build_registry()
    hits: list[tuple[EnginePlugin, float, list[str]]] = []
    for plugin in registry.values():
        try:
            score, evidence = plugin.detect(root)
        except Exception as exc:  # плагин не должен ронять детектор
            score, evidence = 0.0, [f"detect() error: {exc}"]
        if score > 0:
            hits.append((plugin, score, evidence))
    hits.sort(key=lambda x: x[1], reverse=True)
    return hits


__all__ = ["EnginePlugin", "EngineContext", "Dataset", "build_registry", "detect_all"]
