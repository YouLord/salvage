#!/usr/bin/env python3
"""Собирает демо-отчёты (demo/) из синтетического стенда tests/fixtures.

Запуск:  python build_demo.py
Результат: demo/<движок>/report.html|scan.json|report.md + demo/index.html
"""
from __future__ import annotations

import html
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from salvage.core.plugin_base import EngineContext  # noqa: E402
from salvage.core.scan import scan  # noqa: E402
from salvage.report.export import write_json, write_markdown  # noqa: E402
from salvage.report.html import write_html  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
DEMO = ROOT / "demo"

ENGINES = [
    ("unity", "Unity-сборка: индекс, deep-разбор, секреты"),
    ("godot", "Godot: PCK v2, .tscn-зависимости"),
    ("gm", "GameMaker: карта чанков data.win"),
    ("rm_mv", "RPG Maker MV: расшифровка .rpgmvp/.rpgmvo"),
    ("renpy", "Ren'Py: RPA-3.0 архив"),
]


def main() -> None:
    if not (FIX / "unity").is_dir():
        import tests.make_fixtures as mf  # type: ignore
        mf.main()

    if DEMO.exists():
        shutil.rmtree(DEMO)
    DEMO.mkdir(parents=True)

    rows = []
    for slug, note in ENGINES:
        path = FIX / slug
        ds, plugin = scan(path, None, EngineContext(deep=True, log=lambda m: None))
        out = DEMO / slug
        write_html(ds, out / "report.html")
        write_json(ds, out / "scan.json")
        write_markdown(ds, out / "report.md")
        rows.append({
            "slug": slug,
            "engine": ds.engine_name,
            "note": note,
            "files": ds.total_files,
            "findings": len(ds.findings),
            "dir": slug,
        })
        print(f"{slug:<8} {ds.engine_name:<28} ассетов {ds.total_files:>4}  находок {len(ds.findings)}")

    index = ["<!doctype html><html lang='ru'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width,initial-scale=1'>",
             "<title>salvage :: демо-отчёты</title><style>",
             ":root{--bg:#0c0e0d;--panel:#121614;--line:#232925;--ink:#d6dad5;--dim:#8b948e;",
             "--ph:#7ef2a8;--mono:ui-monospace,Consolas,monospace}",
             "body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px;padding:26px 16px}",
             "body{background-image:repeating-linear-gradient(0deg,rgba(126,242,168,.025) 0 1px,transparent 1px 3px)}",
             ".wrap{max-width:900px;margin:0 auto}h1{color:var(--ph);font-size:20px;margin:0 0 4px}",
             ".kicker{color:#5b645e;font-size:10px;letter-spacing:.24em;text-transform:uppercase;margin-bottom:14px}",
             "table{width:100%;border-collapse:collapse;border:1px solid var(--line);background:var(--panel)}",
             "th{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:#5b645e;text-align:left;padding:7px 10px;border-bottom:1px solid var(--line)}",
             "td{padding:8px 10px;border-bottom:1px solid #1a1f1c}td.num{text-align:right;font-variant-numeric:tabular-nums}",
             "a{color:var(--ph)}.dim{color:var(--dim)}.faint{color:#5b645e;font-size:11px}",
             "</style></head><body><div class='wrap'>",
             "<div class='kicker'>salvage // demo reports</div><h1>Отчёты по стенду</h1>",
             "<p class='dim'>Синтетические мини-игры: форматы повторяют реальные контейнеры движков. "
             "Кликните движок, чтобы открыть полный отчёт.</p>",
             "<table><tr><th>движок</th><th>стенд</th><th>ассетов</th><th>находок</th><th>отчёт</th></tr>"]
    for r in rows:
        index.append(
            f"<tr><td><b>{html.escape(r['engine'])}</b><div class='faint'>{html.escape(r['note'])}</div></td>"
            f"<td class='dim'>{r['slug']}</td><td class='num'>{r['files']}</td>"
            f"<td class='num'>{r['findings']}</td>"
            f"<td><a href='{r['dir']}/report.html'>report.html</a> · "
            f"<a href='{r['dir']}/report.md'>md</a> · <a href='{r['dir']}/scan.json'>json</a></td></tr>")
    index.append("</table><p class='faint'>Сгенерировано build_demo.py. Откройте любой report.html — "
                 "он автономен (без внешних ресурсов).</p></div></body></html>")
    (DEMO / "index.html").write_text("".join(index), encoding="utf-8")
    print(f"\nГотово: {DEMO / 'index.html'}")


if __name__ == "__main__":
    main()
