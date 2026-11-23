"""JSON и Markdown-экспорт отчёта (для пайплайнов и PR/issue)."""
from __future__ import annotations

import json
from pathlib import Path

from ..core.model import Dataset
from ..core.util import human_bytes, human_int


def write_json(ds: Dataset, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = ds.to_dict()
    data["tool"] = {"name": "salvage", "version": _version()}
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def export_json_text(ds: Dataset) -> str:
    data = ds.to_dict()
    data["tool"] = {"name": "salvage", "version": _version()}
    return json.dumps(data, ensure_ascii=False, indent=2)


def write_markdown(ds: Dataset, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(ds), encoding="utf-8")
    return path


def render_markdown(ds: Dataset) -> str:
    lines: list[str] = []
    a = lines.append
    findings = ds.findings_by_severity()
    errors = len(findings["error"])
    warns = len(findings["warn"])

    a(f"# Аудит ассетов: {ds.engine_name}")
    a("")
    a(f"**Каталог:** `{ds.root}`  ")
    a(f"**Движок:** {ds.engine_name} (уверенность {ds.score:.2f})  ")
    a(f"**Файлов:** {human_int(ds.total_files)} · **Объём:** {human_bytes(ds.total_size)}  ")
    a(f"**Находок:** {errors} ошибок · {warns} предупреждений · {len(ds.findings)} всего")
    a("")
    a("## Профиль по типам")
    a("")
    a("| Тип | Файлов | Размер |")
    a("|-----|--------|--------|")
    from ..core.util import KIND_LABELS_RU
    for kind, (cnt, size) in ds.kind_stats().items():
        a(f"| {KIND_LABELS_RU.get(kind, kind)} | {human_int(cnt)} | {human_bytes(size)} |")
    a("")
    if ds.findings:
        a("## Находки")
        a("")
        a("| Уровень | Код | Что | Детали |")
        a("|---------|-----|-----|--------|")
        for f in ds.sorted_findings():
            detail = (f.detail or "").replace("\n", " ")[:180]
            a(f"| {f.severity} | `{f.code}` | {f.title} | {detail} |")
        a("")
    doctor = ds.meta.get("doctor")
    if doctor:
        m = doctor["media"]["counts"]
        a("## Врачебный отчёт (doctor)")
        a("")
        a(f"**Здоровье: {doctor['score']}/100 — {doctor['verdict']}**")
        a("")
        a(f"- проверено медиа: {human_int(doctor['media']['checked'])}")
        a(f"- битые изображения: {m['bad_images']} · аудио: {m['bad_audio']} · пустые: {m['empty']}")
        a(f"- аномальные PNG: {len(doctor['pngs'])}")
        a(f"- контейнеры без содержимого: {doctor['containers']['counts']['empty']}")
        a("")
    if ds.extraction:
        a("## Извлечение")
        a("")
        for k in ("extracted", "skipped", "errors", "message"):
            if k in ds.extraction:
                a(f"- {k}: {ds.extraction[k]}")
        a("")
    if ds.meta.get("biggest"):
        a("## Самые крупные файлы")
        a("")
        for item in ds.meta["biggest"]:
            a(f"- `{item['path']}` — {human_bytes(item['bytes'])}")
        a("")
    a("---")
    a(f"*Сгенерировано salvage {_version()}.*")
    return "\n".join(lines) + "\n"


def _version() -> str:
    from .. import __version__
    return __version__
