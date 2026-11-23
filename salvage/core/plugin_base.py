"""Контракт плагина-движка."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .model import Dataset


@dataclass
class EngineContext:
    """Настройки, влияющие на скан и извлечение."""

    deep: bool = False                   # читать контейнеры/бандлы и строить инвентарь
    hash_files: bool = True              # считать sha256 (нужно анализатору дубликатов)
    hash_limit_mb: int = 256             # не хэшировать файлы больше N МБ
    max_asset_bytes: int = 16 << 20      # лимит распаковки одного файла из контейнера
    exclude: list[Path] = field(default_factory=list)
    out_dir: Path | None = None
    keys: dict[str, str] = field(default_factory=dict)   # подсказки ключей (напр. rpgmaker)
    log: Callable[[str], None] = print

    def say(self, msg: str) -> None:
        try:
            self.log(msg)
        except Exception:
            pass


class EnginePlugin:
    """Базовый класс. Плагины обязаны реализовать slug/display_name/detect/scan."""

    slug: str = "base"
    display_name: str = "Base"
    can_extract: bool = False
    notes: str = ""

    # --- идентификация -------------------------------------------------
    def detect(self, root: Path) -> tuple[float, list[str]]:
        """Уверенность 0..1 и список улик (для отчёта)."""
        raise NotImplementedError

    # --- сканирование ---------------------------------------------------
    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        raise NotImplementedError

    # --- извлечение -----------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        """Извлечь ассеты в dest. Возвращает сводку {extracted, skipped, errors, samples}."""
        return {"extracted": 0, "skipped": 0, "errors": 0,
                "message": f"Экстрактор для {self.display_name} не реализован."}

    def __repr__(self) -> str:  # pragma: no cover
        return f"<EnginePlugin {self.slug}>"
