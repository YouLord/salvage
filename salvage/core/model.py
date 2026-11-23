"""Единая модель данных: ассеты, находки, датасет сканирования.

Не зависит от движков. Плагины наполняют Dataset, ядро обогащает его
эвристиками (дубликаты, битые ссылки, энтропия) и сериализует в отчёты.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# Версия схемы scan.json. Правила совместимости — в ROADMAP.md.
# 1 — текущая: engine/totals/meta/assets/findings/extraction + schema_version.
SCHEMA_VERSION = 1

SEVERITY_ORDER = {"error": 0, "warn": 1, "info": 2, "ok": 3}
SEVERITY_TITLES = {
    "error": "ОШИБКА",
    "warn": "ВНИМАНИЕ",
    "info": "ИНФО",
    "ok": "ОК",
}

KIND_ORDER = [
    "texture", "audio", "video", "mesh", "font", "shader",
    "scene", "anim", "script", "data", "archive", "binary", "other",
]


@dataclass
class Asset:
    """Один файл или объект внутри контейнера (бандл, pck, data.win, .rpa)."""

    path: str                      # путь внутри игры (posix), для контейнеров — виртуальный
    kind: str = "other"            # см. core.util.classify
    size: int = 0                  # байт (0 — неизвестно, напр. объект бандла до экспорта)
    container: str | None = None   # файл-контейнер, из которого получен ассет
    sha256: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"path": self.path, "kind": self.kind, "size": self.size}
        if self.container:
            d["container"] = self.container
        if self.sha256:
            d["sha256"] = self.sha256
        if self.extra:
            d["extra"] = _jsonable(self.extra)
        return d


@dataclass
class Finding:
    """Проблема или наблюдение аудита."""

    severity: str            # error | warn | info | ok
    code: str                # машинный код: broken_ref, dup_asset, encrypted, ...
    title: str               # короткая строка для таблицы
    detail: str = ""         # пояснение, примеры
    path: str | None = None  # привязка к ассету
    count: int = 1           # сколько однотипных случаев

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity, "code": self.code, "title": self.title,
            "detail": self.detail, "path": self.path, "count": self.count,
        }


@dataclass
class Dataset:
    """Результат сканирования одной игры одним плагином-движком."""

    engine_slug: str
    engine_name: str
    root: Path
    score: float = 0.0
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    deps: list[tuple[str, str]] = field(default_factory=list)  # (источник, ссылка)
    meta: dict[str, Any] = field(default_factory=dict)
    scan_errors: list[str] = field(default_factory=list)
    extracted_count: int = 0          # сколько файлов реально извлечено в extract
    extraction: dict[str, Any] = field(default_factory=dict)

    # --- наполнение ---------------------------------------------------
    def add_asset(
        self, path: str, kind: str = "other", size: int = 0,
        container: str | None = None, **extra: Any,
    ) -> Asset:
        a = Asset(path=path, kind=kind, size=size, container=container, extra=dict(extra))
        self.assets.append(a)
        return a

    def add_finding(
        self, severity: str, code: str, title: str,
        detail: str = "", path: str | None = None, count: int = 1,
    ) -> Finding:
        f = Finding(severity=severity, code=code, title=title,
                    detail=detail, path=path, count=count)
        self.findings.append(f)
        return f

    def add_dep(self, source: str, ref: str) -> None:
        if ref and source != ref:
            self.deps.append((source, ref))

    # --- сводки ---------------------------------------------------------
    @property
    def total_files(self) -> int:
        return len(self.assets)

    @property
    def total_size(self) -> int:
        return sum(a.size for a in self.assets)

    def kind_stats(self) -> dict[str, tuple[int, int]]:
        """kind -> (количество, суммарный размер)."""
        stats: dict[str, list[int]] = {}
        for a in self.assets:
            s = stats.setdefault(a.kind, [0, 0])
            s[0] += 1
            s[1] += a.size
        ordered = {k: (v[0], v[1]) for k, v in
                   sorted(stats.items(), key=lambda kv: _kind_key(kv[0]))}
        return ordered

    def findings_by_severity(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {"error": [], "warn": [], "info": [], "ok": []}
        for f in sorted(self.findings, key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), x.code)):
            out.setdefault(f.severity, []).append(f)
        return out

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings,
                      key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), -x.count, x.code))

    def biggest(self, n: int = 20) -> list[Asset]:
        return sorted(self.assets, key=lambda a: a.size, reverse=True)[:n]

    def to_dict(self, asset_limit: int = 50_000) -> dict[str, Any]:
        from .. import __version__

        return {
            "schema_version": SCHEMA_VERSION,
            "generator_version": __version__,
            "engine": self.engine_slug,
            "engine_name": self.engine_name,
            "detection_score": round(self.score, 3),
            "root": str(self.root),
            "totals": {
                "files": self.total_files,
                "bytes": self.total_size,
                "kinds": {k: {"count": c, "bytes": b}
                          for k, (c, b) in self.kind_stats().items()},
            },
            "meta": _jsonable(self.meta),
            "assets": [a.to_dict() for a in self.assets[:asset_limit]],
            "assets_truncated": max(0, len(self.assets) - asset_limit),
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "dependencies_total": len(self.deps),
            "extracted_count": self.extracted_count,
            "extraction": _jsonable(self.extraction),
            "scan_errors": self.scan_errors,
        }


def _kind_key(kind: str) -> tuple[int, str]:
    try:
        return (KIND_ORDER.index(kind), kind)
    except ValueError:
        return (len(KIND_ORDER), kind)


def _jsonable(value: Any) -> Any:
    if hasattr(value, "entries") and hasattr(value, "version"):  # PakFile и подобные
        return {"__object__": type(value).__name__,
                "version": getattr(value, "version", None),
                "entries": len(getattr(value, "entries", []) or [])}
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)
