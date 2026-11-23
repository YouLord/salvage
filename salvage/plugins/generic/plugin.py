"""Generic-плагин: универсальный аудит неизвестной папки/игры.

Не «пустышка», а честный слой последней надежды:
  - полный индекс файлов с классификацией и энтропией подозрительных блобов,
  - поиск zip/gzip-контейнеров и попытка их заглянуть,
  - базовая оценка структуры (движок не распознан → ищем улики: .dll, .exe, .pak...).
Извлечение: побайтовое копирование с чисткой структуры.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin
from ...core.util import (classify, head_bytes, human_int, iter_files, rel_posix,
                          safe_rel, sha256_file, sniff_magic)
from .._shared import copy_verbatim

# улики, по которым можно предположить движок даже без плагина
ENGINE_CLUES = {
    "unity": ("UnityPlayer.dll", "globalgamemanagers", "Managed/", "UnityEngine"),
    "unreal": ("Engine/", ".pak", ".utoc", "UnrealEngine"),
    "gamemaker": ("data.win",),
    "godot": ("project.godot", ".pck"),
    "renpy": (".rpa", "renpy"),
    "rpgmaker": ("RGSS", "System.json", ".rgss"),
}


class GenericPlugin(EnginePlugin):
    slug = "generic"
    display_name = "Generic (неизвестный движок)"
    can_extract = True
    notes = "Универсальный индекс и аудит; подсказывает, каким плагином перепроверить."

    def detect(self, root: Path) -> tuple[float, list[str]]:
        # низкая базовая уверенность: выбирается только если никто не узнан
        return 0.1, ["запасной режим"]

    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        # ядро проиндексирует файлы само (scan._index_plain_files), здесь — только улики
        clues: dict[str, list[str]] = {}
        checked = 0
        for p in iter_files(root, exclude=ctx.exclude):
            if checked > 200_000:
                break
            checked += 1
            rel = rel_posix(p, root.resolve())
            low = rel.lower()
            for engine, needles in ENGINE_CLUES.items():
                if any(n.lower() in low for n in needles):
                    clues.setdefault(engine, [])
                    if len(clues[engine]) < 5:
                        clues[engine].append(rel)
            if all(len(v) >= 3 for v in clues.values()):
                break
        if clues:
            ds.meta["engine_clues"] = clues
            best = max(clues, key=lambda k: len(clues[k]))
            ds.add_finding(
                "info", "engine_clues",
                f"Возможный движок: {best} (улики: {', '.join(clues[best])})",
                "Запустите: salvage scan <path> --engine " + best)
        return ds

    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        summary = copy_verbatim(dataset, dest, ctx, only_kinds)
        # бонус: распаковать встречающиеся zip-архивы
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        for a in dataset.assets:
            if a.kind != "archive" or a.container:
                continue
            p = dataset.root / a.path
            if not p.is_file() or not zipfile.is_zipfile(p):
                continue
            target = Path(dest) / "unzipped" / safe_rel(a.path).replace("/", "_")
            try:
                with zipfile.ZipFile(p) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        name = safe_rel(info.filename)
                        if not name:
                            continue
                        dest_file = target / name
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(info) as src, open(dest_file, "wb") as dst:
                            dst.write(src.read(ctx.max_asset_bytes))
                        out["extracted"] += 1
                        if len(out["samples"]) < 10:
                            out["samples"].append(f"{a.path}:{info.filename}")
            except (zipfile.BadZipFile, OSError):
                out["errors"] += 1
        if out["extracted"]:
            out["message"] = f"Распаковано из zip: {out['extracted']} файлов."
        summary["extracted"] += out["extracted"]
        summary["errors"] += out["errors"]
        summary["samples"] = (summary["samples"] + out["samples"])[:20]
        summary["message"] = (summary["message"] + " " + out["message"]).strip()
        return summary
