"""Общие помощники плагинов."""
from __future__ import annotations

import shutil
from pathlib import Path

from ..core.model import Dataset
from ..core.plugin_base import EngineContext
from ..core.util import human_bytes, safe_rel


def copy_verbatim(ds: Dataset, dest: Path, ctx: EngineContext,
                  only_kinds: set[str] | None = None, subdir: str = "files",
                  skip_kinds: set[str] | None = None) -> dict:
    """Побайтовое копирование учтённых файлов (базовый уровень извлечения)."""
    extracted = skipped = errors = 0
    samples: list[str] = []
    dest = Path(dest)
    root = ds.root
    for a in ds.assets:
        if a.container:
            continue  # контент контейнеров извлекают специализированные экстракторы
        if only_kinds and a.kind not in only_kinds:
            skipped += 1
            continue
        if skip_kinds and a.kind in skip_kinds:
            skipped += 1
            continue  # контейнер уже распакован специализированным экстрактором
        src = root / a.path
        if not src.is_file():
            skipped += 1
            continue
        target = dest / subdir / safe_rel(a.path)
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
            extracted += 1
            if len(samples) < 12:
                samples.append(a.path)
        except OSError as exc:
            errors += 1
            if len(samples) < 12:
                samples.append(f"! {a.path}: {exc}")
    return {
        "extracted": extracted, "skipped": skipped, "errors": errors,
        "bytes": ds.total_size, "samples": samples,
        "message": f"Скопировано {extracted} файлов ({human_bytes(ds.total_size)}).",
    }


def merge_summaries(a: dict, b: dict) -> dict:
    out = {
        "extracted": a.get("extracted", 0) + b.get("extracted", 0),
        "skipped": a.get("skipped", 0) + b.get("skipped", 0),
        "errors": a.get("errors", 0) + b.get("errors", 0),
        "samples": (a.get("samples") or []) + (b.get("samples") or []),
        "message": "; ".join(m for m in (a.get("message"), b.get("message")) if m),
    }
    out["samples"] = out["samples"][:20]
    return out
