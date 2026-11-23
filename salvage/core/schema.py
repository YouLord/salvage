"""Схема scan.json: версия и валидатор.

Зачем: отчётом пользуются снаружи (веб-пульт, скрипты), и молчаливая смена
структуры ломает потребителей. ``schema_version`` увеличивается при
несовместимом изменении; ``validate_scan_json`` возвращает СПИСОК проблем,
а не бросает исключение — вызывающий сам решает, падать или предупреждать.
"""
from __future__ import annotations

from typing import Any

SCHEMA_VERSION = 1

#: Минимально обязательные поля верхнего уровня.
REQUIRED_TOP = ("schema_version", "engine", "engine_name", "totals",
                "assets", "findings", "meta")
REQUIRED_TOTALS = ("files", "bytes")
REQUIRED_ASSET = ("path", "kind", "size")

#: Поля, которые появились в версии 1 и без которых дамп считается старым.
V1_FIELDS = ("extraction", "meta", "findings")


def validate_scan_json(doc: Any) -> list[str]:
    """Проверить дамп scan.json. Пустой список = проблем нет.

    Дамп без ``schema_version`` не отвергается: это старый вывод, который
    надо прочитать с предупреждением. Ошибки структуры (нет totals, assets
    не список, у ассета нет size) — реальные, их возвращаем как проблемы.
    """
    problems: list[str] = []
    if not isinstance(doc, dict):
        return ["корень scan.json должен быть объектом"]

    if "schema_version" not in doc:
        problems.append("нет schema_version — вероятно, дамп старой версии; "
                        "прочитан с предупреждением")
        doc = {**doc, "schema_version": SCHEMA_VERSION}
    else:
        version = doc["schema_version"]
        if not isinstance(version, int):
            problems.append("schema_version должен быть целым числом")
        elif version > SCHEMA_VERSION:
            problems.append(
                f"schema_version={version} новее поддерживаемой {SCHEMA_VERSION}: "
                "обновите читающую сторону")

    for key in REQUIRED_TOP:
        if key in ("schema_version",):
            continue
        if key not in doc:
            problems.append(f"нет обязательного поля {key}")
    totals = doc.get("totals")
    if isinstance(totals, dict):
        for key in REQUIRED_TOTALS:
            if key not in totals:
                problems.append(f"нет totals.{key}")
    elif totals is not None:
        problems.append("totals должен быть объектом")

    assets = doc.get("assets")
    if assets is not None:
        if not isinstance(assets, list):
            problems.append("assets должен быть списком")
        else:
            for i, a in enumerate(assets[:50]):
                if not isinstance(a, dict):
                    problems.append(f"assets[{i}] должен быть объектом")
                    continue
                for key in REQUIRED_ASSET:
                    if key not in a:
                        problems.append(f"assets[{i}]: нет поля {key}")

    findings = doc.get("findings")
    if findings is not None:
        if not isinstance(findings, list):
            problems.append("findings должен быть списком")
        else:
            for i, f in enumerate(findings[:50]):
                if not isinstance(f, dict):
                    problems.append(f"findings[{i}] должен быть объектом")
                    continue
                for key in ("severity", "code", "title"):
                    if key not in f:
                        problems.append(f"findings[{i}]: нет поля {key}")

    extraction = doc.get("extraction")
    if extraction is not None and not isinstance(extraction, dict):
        problems.append("extraction должен быть объектом")

    meta = doc.get("meta")
    if meta is not None and not isinstance(meta, dict):
        problems.append("meta должен быть объектом")

    return problems


def load_scan_json(path) -> tuple[dict, list[str]]:
    """Прочитать дамп и вернуть (документ, проблемы). Битый JSON — исключение."""
    import json
    from pathlib import Path

    doc = json.loads(Path(path).read_text("utf-8"))
    return doc, validate_scan_json(doc)
