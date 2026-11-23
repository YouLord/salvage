"""Оркестратор: детект движка → обход файлов → анализ → Dataset."""
from __future__ import annotations

from pathlib import Path

from .analyze import run_analyzers
from .model import Dataset
from .plugin_base import EngineContext, EnginePlugin
from .registry import build_registry, detect_all
from .util import ext_of, human_int, iter_files, rel_posix, sha256_file, sniff_magic, head_bytes, classify


class ScanError(RuntimeError):
    pass


def resolve_plugin(root: Path, engine: str | None = None) -> tuple[EnginePlugin, float, list[str]]:
    registry = build_registry()
    if engine:
        if engine not in registry:
            raise ScanError(f"Неизвестный движок '{engine}'. Доступны: {', '.join(sorted(registry))}")
        if engine == "generic":
            return registry["generic"], 0.0, ["выбран принудительно"]
        score, evidence = registry[engine].detect(root)
        return registry[engine], score, evidence
    hits = detect_all(root, registry)
    if not hits:
        return registry["generic"], 0.0, ["автодетект не распознал движок"]
    return hits[0]


def scan(root: Path, engine: str | None = None, ctx: EngineContext | None = None
         ) -> tuple[Dataset, EnginePlugin]:
    root = Path(root)
    if not root.exists():
        raise ScanError(f"Путь не существует: {root}")
    if not root.is_dir():
        root = root.parent
    ctx = ctx or EngineContext()

    plugin, score, evidence = resolve_plugin(root, engine)
    ctx.say(f"Движок: {plugin.display_name} (уверенность {score:.2f})")
    for ev in evidence[:5]:
        ctx.say(f"  улика: {ev}")

    ds = plugin.scan(root, ctx)
    ds.score = score
    ds.meta.setdefault("detection_evidence", evidence)

    # общий обход: файлы, которые плагин не учёл сам, добавляем как обычные ассеты
    if plugin.slug == "generic" or not ds.assets:
        _index_plain_files(root, ds, ctx)

    run_analyzers(ds, ctx)
    ctx.say(f"Проиндексировано: {human_int(ds.total_files)} ассетов, "
            f"{human_int(len(ds.findings))} находок")
    return ds, plugin


def _index_plain_files(root: Path, ds: Dataset, ctx: EngineContext) -> None:
    known = {a.path for a in ds.assets}
    root_r = root.resolve()
    for p in iter_files(root, exclude=ctx.exclude):
        rel = rel_posix(p, root_r)
        if rel in known:
            continue
        try:
            size = p.stat().st_size
        except OSError:
            size = 0
        head = head_bytes(p, 16) if size else b""
        magic = sniff_magic(head, rel)
        kind = classify(rel, magic)
        sha = None
        if ctx.hash_files and size and size <= ctx.hash_limit_mb * (1 << 20):
            sha = sha256_file(p)
        a = ds.add_asset(rel, kind=kind, size=size, sha256=sha)
        if magic:
            a.extra["magic"] = magic
