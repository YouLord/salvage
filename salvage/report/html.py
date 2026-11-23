"""Генератор автономного HTML-отчёта.

Дизайн намеренно «инструментальный»: монотипографика, фосфорный акцент,
плотные таблицы, без градиентов и скруглений. Всё inline, без внешних ресурсов.
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path

from ..core.model import Dataset, SEVERITY_TITLES
from ..core.util import KIND_LABELS_RU, human_bytes, human_int

CSS = """
:root{
  --bg:#0d0f0e; --panel:#141816; --panel2:#181d1a; --line:#252b27;
  --ink:#d7dbd6; --dim:#8a938d; --faint:#5c655f;
  --ph:#7ef2a8; --ph-dim:#2f7a4f; --err:#ff6a5e; --warn:#ffc44d; --info:#6fb7ff; --ok:#57d98a;
  --mono:ui-monospace,"SFMono-Regular","Cascadia Mono","JetBrains Mono",Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px;line-height:1.5}
body{background-image:linear-gradient(rgba(126,242,168,.028) 1px,transparent 1px);background-size:100% 3px;padding:24px 18px 60px}
.wrap{max-width:1180px;margin:0 auto}
a{color:var(--ph)}
h1,h2,h3{font-weight:600;letter-spacing:.02em;margin:0}
.kicker{color:var(--faint);text-transform:uppercase;letter-spacing:.22em;font-size:10px}
.title{font-size:22px;color:var(--ph);text-shadow:0 0 18px rgba(126,242,168,.25)}
header{border:1px solid var(--line);background:var(--panel);padding:16px 18px;margin-bottom:14px}
header .meta{color:var(--dim);margin-top:6px;word-break:break-all}
.status{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
.chip{border:1px solid var(--line);padding:3px 9px;font-size:11px;color:var(--dim)}
.chip b{color:var(--ink)}
.chip.e{border-color:#5a2621;color:var(--err)} .chip.w{border-color:#5a4720;color:var(--warn)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin-bottom:14px}
.cell{background:var(--panel);padding:12px 14px}
.cell .v{font-size:20px;color:var(--ph);font-variant-numeric:tabular-nums}
.cell .l{color:var(--faint);font-size:10px;text-transform:uppercase;letter-spacing:.14em;margin-top:2px}
section{border:1px solid var(--line);background:var(--panel);margin-bottom:14px}
section>h2{font-size:12px;text-transform:uppercase;letter-spacing:.18em;color:var(--dim);padding:10px 14px;border-bottom:1px solid var(--line);background:var(--panel2)}
section .body{padding:14px}
table{width:100%;border-collapse:collapse}
th{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--faint);text-align:left;padding:4px 10px 6px;border-bottom:1px solid var(--line);font-weight:500}
td{padding:5px 10px;border-bottom:1px solid #1b201d;vertical-align:top}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tr:hover td{background:#171c19}
.sev{font-size:10px;letter-spacing:.1em;padding:1px 6px;border:1px solid var(--line);white-space:nowrap}
.sev.error{color:var(--err);border-color:#5a2621}
.sev.warn{color:var(--warn);border-color:#5a4720}
.sev.info{color:var(--info);border-color:#24405e}
.sev.ok{color:var(--ok);border-color:#1f4a33}
.detail{color:var(--dim);font-size:12px}
.mono-s{color:var(--faint)}
.bar{height:3px;background:var(--ph-dim);margin-top:4px;min-width:2px}
.kind-name{color:var(--ink)}
.note{color:var(--faint);font-size:11px;padding:2px 14px 12px}
footer{color:var(--faint);font-size:11px;text-align:center;margin-top:22px;letter-spacing:.06em}
.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:840px){.cols{grid-template-columns:1fr}}
pre{white-space:pre-wrap;word-break:break-word;background:#101412;border:1px solid var(--line);padding:10px;color:var(--dim);font-size:11px;margin:8px 0 0}
"""


def _esc(s) -> str:
    return html.escape(str(s if s is not None else ""))


def render_html(ds: Dataset) -> str:
    findings = ds.findings_by_severity()
    errors = len(findings["error"])
    warns = len(findings["warn"])
    infos = len(findings["info"])
    oks = len(findings["ok"])

    parts: list[str] = []
    p = parts.append
    p("<!doctype html><html lang='ru'><head><meta charset='utf-8'>")
    p("<meta name='viewport' content='width=device-width,initial-scale=1'>")
    p(f"<title>salvage · {_esc(ds.engine_name)}</title><style>{CSS}</style></head><body><div class='wrap'>")

    # --- шапка ---
    p("<header>")
    p("<div class='kicker'>salvage // asset audit</div>")
    p(f"<h1 class='title'>{_esc(ds.engine_name)}</h1>")
    p(f"<div class='meta'>каталог: {_esc(ds.root)}</div>")
    p("<div class='status'>")
    p(f"<span class='chip e'><b>{errors}</b> ошибок</span>")
    p(f"<span class='chip w'><b>{warns}</b> предупреждений</span>")
    p(f"<span class='chip'><b>{infos}</b> инфо · <b>{oks}</b> ок</span>")
    p(f"<span class='chip'>движок: <b>{_esc(ds.engine_slug)}</b> @ {ds.score:.2f}</span>")
    p(f"<span class='chip'>сгенерировано: <b>{datetime.now().strftime('%Y-%m-%d %H:%M')}</b></span>")
    p("</div></header>")

    # --- сводка ---
    p("<div class='grid'>")
    cells = [
        (human_int(ds.total_files), "ассетов всего"),
        (human_bytes(ds.total_size), "объём"),
        (human_int(len(ds.deps)), "зависимостей"),
        (human_int(errors + warns), "проблем"),
    ]
    if ds.extracted_count:
        cells.append((human_int(ds.extracted_count), "извлечено файлов"))
    for v, l in cells:
        p(f"<div class='cell'><div class='v'>{v}</div><div class='l'>{l}</div></div>")
    p("</div>")

    # --- doctor ---
    doctor = ds.meta.get("doctor")
    if doctor:
        m = doctor["media"]["counts"]
        score = doctor["score"]
        color = ("var(--ok)" if score >= 90 else "var(--info)" if score >= 75
                 else "var(--warn)" if score >= 50 else "var(--err)")
        p("<section><h2>Врачебный отчёт (doctor)</h2><div class='body'>")
        p(f"<div style='font-size:20px;color:{color}'>здоровье: {score}/100 — "
          f"{_esc(doctor['verdict'])}</div>")
        p("<table style='margin-top:8px'>")
        rows = [
            ("проверено медиа", human_int(doctor["media"]["checked"])),
            ("битые изображения", human_int(m["bad_images"])),
            ("битые аудио", human_int(m["bad_audio"])),
            ("пустые файлы", human_int(m["empty"])),
            ("аномальные PNG", human_int(len(doctor["pngs"]))),
            ("контейнеры без содержимого", human_int(doctor["containers"]["counts"]["empty"])),
        ]
        for label, val in rows:
            p(f"<tr><td class='dim'>{label}</td><td class='num'>{val}</td></tr>")
        p("</table></div></section>")

    # --- извлечение ---
    if ds.extraction:
        exc = ds.extraction
        p("<section><h2>Извлечение</h2><div class='body'><table>")
        p("<tr><th>метрика</th><th>значение</th></tr>")
        for k in ("extracted", "skipped", "errors", "message"):
            if k in exc:
                p(f"<tr><td class='dim'>{_esc(k)}</td><td>{_esc(exc[k])}</td></tr>")
        p("</table></div></section>")

    # --- типы ---
    p("<section><h2>Профиль контента</h2><div class='body'><table>")
    p("<tr><th>тип</th><th>файлов</th><th>размер</th><th style='width:35%'>доля</th></tr>")
    total = max(ds.total_size, 1)
    for kind, (cnt, size) in ds.kind_stats().items():
        pct = max(1, round(size / total * 100))
        p("<tr>")
        p(f"<td class='kind-name'>{_esc(KIND_LABELS_RU.get(kind, kind))}</td>")
        p(f"<td class='num'>{human_int(cnt)}</td>")
        p(f"<td class='num'>{human_bytes(size)}</td>")
        p(f"<td><div class='bar' style='width:{pct}%'></div><span class='mono-s'>{pct}%</span></td>")
        p("</tr>")
    p("</table></div></section>")

    # --- находки ---
    if ds.findings:
        p("<section><h2>Находки</h2><div class='body'><table>")
        p("<tr><th style='width:90px'>уровень</th><th style='width:150px'>код</th><th>что обнаружено</th><th style='width:60px'>шт.</th></tr>")
        for f in ds.sorted_findings():
            label = SEVERITY_TITLES.get(f.severity, f.severity.upper())
            p("<tr>")
            p(f"<td><span class='sev {_esc(f.severity)}'>{_esc(label)}</span></td>")
            p(f"<td class='mono-s'>{_esc(f.code)}</td>")
            p(f"<td>{_esc(f.title)}")
            if f.detail:
                p(f"<div class='detail'>{_esc(f.detail)}</div>")
            if f.path:
                p(f"<div class='mono-s'>{_esc(f.path)}</div>")
            p("</td>")
            p(f"<td class='num'>{human_int(f.count)}</td>")
            p("</tr>")
        p("</table></div></section>")

    # --- дубликаты / битые ссылки / энтропия ---
    col_blocks: list[str] = []
    if ds.meta.get("duplicates"):
        rows = "".join(
            f"<tr><td>{_esc(d['copies'][0])}</td><td class='num'>{len(d['copies'])}</td>"
            f"<td class='num'>{human_bytes(d['size'])}</td></tr>"
            for d in ds.meta["duplicates"][:25]
        )
        col_blocks.append(
            "<div><h3 style='color:var(--dim);font-size:11px;text-transform:uppercase;"
            "letter-spacing:.14em;margin-bottom:6px'>Дубликаты</h3>"
            "<table><tr><th>эталон</th><th>копий</th><th>размер</th></tr>"
            f"{rows}</table></div>"
        )
    if ds.meta.get("broken_refs"):
        rows = "".join(
            f"<tr><td>{_esc(b['target'])}</td><td class='mono-s'>{_esc(b['source'])}</td></tr>"
            for b in ds.meta["broken_refs"][:25]
        )
        col_blocks.append(
            "<div><h3 style='color:var(--dim);font-size:11px;text-transform:uppercase;"
            "letter-spacing:.14em;margin-bottom:6px'>Битые ссылки</h3>"
            "<table><tr><th>цель</th><th>источник</th></tr>"
            f"{rows}</table></div>"
        )
    if col_blocks:
        p(f"<section><h2>Разбор ссылок и дубликатов</h2><div class='body'><div class='cols'>{''.join(col_blocks)}</div></div></section>")

    # --- крупнейшие файлы ---
    if ds.meta.get("biggest"):
        p("<section><h2>Самые тяжёлые файлы</h2><div class='body'><table>")
        p("<tr><th>путь</th><th style='width:110px'>размер</th></tr>")
        for item in ds.meta["biggest"]:
            p(f"<tr><td>{_esc(item['path'])}</td><td class='num'>{human_bytes(item['bytes'])}</td></tr>")
        p("</table></div></section>")

    # --- мета движка ---
    meta_view = {k: v for k, v in ds.meta.items()
                 if k not in ("duplicates", "broken_refs", "biggest", "high_entropy",
                              "secrets", "containers", "detection_evidence", "_rm_key")}
    if meta_view:
        p("<section><h2>Метаданные движка</h2><div class='body'>")
        from ..core.model import _jsonable
        p(f"<pre>{_esc(json.dumps(_jsonable(meta_view), ensure_ascii=False, indent=1)[:12000])}</pre>")
        p("</div></section>")

    # --- секреты ---
    if ds.meta.get("secrets"):
        p("<section><h2>Инвентарь чувствительных строк</h2><div class='body'><table>")
        p("<tr><th>категория</th><th>файл</th><th>совпадение</th></tr>")
        for cat, items in ds.meta["secrets"].items():
            for it in items[:15]:
                p(f"<tr><td>{_esc(cat)}</td><td>{_esc(it['path'])}</td>"
                  f"<td class='mono-s'>{_esc(it['match'])}</td></tr>")
        p("</table><div class='note'>Это эвристика: не все строки — реальные секреты. "
          "Данные остаются локально, отчёт не передаётся наружу.</div></div></section>")

    p(f"<footer>salvage · отчёт сгенерирован автоматом · {date_stamp()}</footer>")
    p("</div></body></html>")
    return "".join(parts)


def date_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d")


def write_html(ds: Dataset, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(ds), encoding="utf-8")
    return path
