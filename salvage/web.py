"""Локальный веб-пульт: python -m salvage.web [--port 8741]

Без фреймворков (http.server). По умолчанию слушает 127.0.0.1: пульт локальный
и не должен торчать в сеть сам по себе. ``--host 0.0.0.0`` — только явно
(нужно, например, для live-preview в песочнице).
Страница автономна: ни одного внешнего <script>/<link>/src=http — иначе пульт
ломается без интернета и стучится наружу. Стиль — намеренно «терминальный».
"""
from __future__ import annotations

import argparse
import html as _html
import json
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core.model import SEVERITY_TITLES
from .core.plugin_base import EngineContext
from .core.registry import build_registry
from .core.scan import scan
from .core.util import KIND_LABELS_RU, human_bytes, human_int

_CACHE: dict[str, tuple[str, object]] = {}
_RUNNING = threading.Lock()
_FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

CSS = """
:root{--bg:#0c0e0d;--panel:#121614;--line:#232925;--ink:#d6dad5;--dim:#8b948e;
--faint:#5b645e;--ph:#7ef2a8;--err:#ff6a5e;--warn:#ffc44d;--info:#6fb7ff;--ok:#57d98a;
--mono:ui-monospace,"SFMono-Regular","Cascadia Mono",Consolas,monospace}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--mono);font-size:13px;line-height:1.55}
body{background-image:repeating-linear-gradient(0deg,rgba(126,242,168,.025) 0 1px,transparent 1px 3px)}
.wrap{max-width:1180px;margin:0 auto;padding:22px 16px 70px}
header{border:1px solid var(--line);background:var(--panel);padding:14px 16px;margin-bottom:12px}
.kicker{color:var(--faint);font-size:10px;letter-spacing:.24em;text-transform:uppercase}
h1{font-size:20px;color:var(--ph);margin:2px 0 0;font-weight:600}
h1 small{color:var(--faint);font-size:11px;font-weight:400}
.sub{color:var(--dim);margin-top:4px;font-size:12px}
form{display:grid;grid-template-columns:1fr auto auto;gap:8px;border:1px solid var(--line);background:var(--panel);padding:12px;margin-bottom:12px}
input[type=text]{background:#0a0c0b;border:1px solid var(--line);color:var(--ink);font-family:var(--mono);font-size:13px;padding:8px 10px;width:100%}
input[type=text]:focus{outline:none;border-color:var(--ph)}
select{background:#0a0c0b;border:1px solid var(--line);color:var(--ink);font-family:var(--mono);font-size:13px;padding:8px}
button{background:var(--panel);border:1px solid var(--ph);color:var(--ph);font-family:var(--mono);font-size:12px;letter-spacing:.1em;text-transform:uppercase;padding:8px 16px;cursor:pointer}
button:hover{background:#152a1d}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
.chip{border:1px solid var(--line);padding:2px 8px;font-size:11px;color:var(--dim);cursor:pointer;background:var(--panel)}
.chip:hover{border-color:var(--ph);color:var(--ph)}
section{border:1px solid var(--line);background:var(--panel);margin-bottom:12px}
section>h2{font-size:11px;text-transform:uppercase;letter-spacing:.2em;color:var(--dim);padding:9px 12px;border-bottom:1px solid var(--line);margin:0;background:#101412}
.body{padding:12px}
table{width:100%;border-collapse:collapse}th{font-size:10px;text-transform:uppercase;letter-spacing:.12em;color:var(--faint);text-align:left;padding:4px 8px;border-bottom:1px solid var(--line);font-weight:500}
td{padding:4px 8px;border-bottom:1px solid #1a1f1c;vertical-align:top}td.num{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.sev{font-size:10px;padding:1px 6px;border:1px solid var(--line);white-space:nowrap}
.sev.error{color:var(--err);border-color:#5a2621}.sev.warn{color:var(--warn);border-color:#5a4720}
.sev.info{color:var(--info);border-color:#24405e}.sev.ok{color:var(--ok);border-color:#1f4a33}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin-bottom:12px}
.cell{background:var(--panel);padding:10px 12px}.cell .v{font-size:19px;color:var(--ph);font-variant-numeric:tabular-nums}.cell .l{font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.14em}
a{color:var(--ph)}.dim{color:var(--dim)}.faint{color:var(--faint)}
pre{background:#0a0c0b;border:1px solid var(--line);padding:10px;font-size:11px;color:var(--dim);overflow:auto;max-height:420px;white-space:pre-wrap;word-break:break-all}
footer{margin-top:20px;text-align:center;color:var(--faint);font-size:11px;letter-spacing:.08em}
.bar{height:3px;background:#2f7a4f;margin-top:3px;min-width:2px}
.warnbox{border:1px solid #5a4720;color:var(--warn);padding:8px 12px;font-size:12px;margin-bottom:12px;background:#171411}
"""


def page(title: str, body: str) -> str:
    return ("<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{_html.escape(title)}</title><style>{CSS}</style></head>"
            f"<body><div class='wrap'>{body}<footer>salvage :: локальный пульт · данные не покидают машину</footer></div></body></html>")


def index_page(default_path: str = "") -> str:
    reg = build_registry()
    engine_opts = "<option value=''>автодетект</option>" + "".join(
        f"<option value='{_html.escape(p.slug)}'>{_html.escape(p.display_name)}</option>"
        for p in reg.values())
    chips = ""
    if _FIXTURES.is_dir():
        chips = "<div class='chips'><span class='faint'>стенд для проверки →</span>" + "".join(
            f"<span class='chip' onclick=\"document.getElementById('path').value='{_html.escape(str(p))}'\">{_html.escape(p.name)}</span>"
            for p in sorted(_FIXTURES.iterdir()) if p.is_dir())
        chips += "</div>"
    body = f"""
<header>
  <div class='kicker'>asset forensics console</div>
  <h1>salvage <small>/ локальный аудит ассетов</small></h1>
  <div class='sub'>Unity · Godot · GameMaker · RPG Maker · Ren'Py · generic</div>
</header>
<form method='get' action='/scan'>
  <input type='text' id='path' name='path' value='{_html.escape(default_path)}' placeholder='/путь/к/игре или проекту'>
  <select name='engine'>{engine_opts}</select>
  <button type='submit'>сканировать</button>
  <label class='faint' style='grid-column:1/-1;font-size:11px'>
    <input type='checkbox' name='deep' value='1' checked> глубокий скан (разбор контейнеров и зависимостей)
  </label>
</form>
{chips}
<div class='warnbox'>Пульт слушает только этот компьютер. Не публикуйте отчёты с секциями «чувствительные строки» в открытый доступ.</div>
<section><h2>что умеет</h2><div class='body'>
<table>
<tr><th>движок</th><th>что разбирает</th></tr>
{"".join(f"<tr><td>{_html.escape(p.display_name)}</td><td class='dim'>{_html.escape(p.notes)}</td></tr>" for p in reg.values())}
</table></div></section>
"""
    return page("salvage :: пульт", body)


def result_page(path: Path, engine: str, deep: bool) -> str:
    with _RUNNING:
        ds, plugin = scan(path, engine or None, EngineContext(deep=deep, log=lambda m: None))
        from .core.doctor import run_doctor
        doctor = run_doctor(ds)
    summary = ds.to_dict(asset_limit=500)
    by = ds.findings_by_severity()
    errs, warns = len(by["error"]), len(by["warn"])

    kind_rows = "".join(
        f"<tr><td>{KIND_LABELS_RU.get(k, k)}</td><td class='num'>{human_int(c)}</td>"
        f"<td class='num'>{human_bytes(b)}</td><td style='width:30%'><div class='bar' style='width:{max(1, round(b / max(ds.total_size,1) * 100))}%'></div></td></tr>"
        for k, (c, b) in ds.kind_stats().items())

    find_rows = "".join(
        f"<tr><td><span class='sev {f.severity}'>{SEVERITY_TITLES.get(f.severity, f.severity)}</span></td>"
        f"<td class='faint'>{_html.escape(f.code)}</td><td>{_html.escape(f.title)}"
        + (f"<div class='dim' style='font-size:11px'>{_html.escape(f.detail)}</div>" if f.detail else "")
        + f"</td><td class='num'>{human_int(f.count)}</td></tr>"
        for f in ds.sorted_findings())

    assets_rows = "".join(
        f"<tr><td>{_html.escape(a.path)}</td><td class='faint'>{_html.escape(a.kind)}</td>"
        f"<td class='num'>{human_bytes(a.size) if a.size else '—'}</td>"
        f"<td class='faint'>{_html.escape(a.container or '')}</td></tr>"
        for a in ds.assets[:500])

    meta_json = _html.escape(json.dumps(
        {k: v for k, v in ds.meta.items() if k not in ("_rm_key",)}, ensure_ascii=False,
        indent=1)[:20000])

    body = f"""
<header>
  <div class='kicker'>scan result</div>
  <h1>{_html.escape(ds.engine_name)} <small>@ {_html.escape(str(ds.root))}</small></h1>
  <div class='sub'>уверенность детекта: {ds.score:.2f} · находок: {len(ds.findings)} · <a href='/'>← новый скан</a></div>
</header>
<div class='grid'>
  <div class='cell'><div class='v'>{human_int(ds.total_files)}</div><div class='l'>ассетов</div></div>
  <div class='cell'><div class='v'>{human_bytes(ds.total_size)}</div><div class='l'>объём</div></div>
  <div class='cell'><div class='v'>{errs}</div><div class='l'>ошибок</div></div>
  <div class='cell'><div class='v'>{warns}</div><div class='l'>предупреждений</div></div>
  <div class='cell'><div class='v'>{len(ds.deps)}</div><div class='l'>зависимостей</div></div>
</div>
<section><h2>врачебный отчёт</h2><div class='body'>
<div style='font-size:19px;color:{"var(--ok)" if doctor["score"] >= 90 else "var(--info)" if doctor["score"] >= 75 else "var(--warn)" if doctor["score"] >= 50 else "var(--err)"}'>
здоровье: {doctor["score"]}/100 — {_html.escape(doctor["verdict"])}</div>
<table style='margin-top:8px'>
<tr><td class='dim'>проверено медиа</td><td class='num'>{human_int(doctor["media"]["checked"])}</td></tr>
<tr><td class='dim'>битые изображения</td><td class='num'>{doctor["media"]["counts"]["bad_images"]}</td></tr>
<tr><td class='dim'>битые аудио</td><td class='num'>{doctor["media"]["counts"]["bad_audio"]}</td></tr>
<tr><td class='dim'>пустые файлы</td><td class='num'>{doctor["media"]["counts"]["empty"]}</td></tr>
<tr><td class='dim'>аномальные PNG</td><td class='num'>{len(doctor["pngs"])}</td></tr>
<tr><td class='dim'>контейнеры без содержимого</td><td class='num'>{doctor["containers"]["counts"]["empty"]}</td></tr>
</table></div></section>
<section><h2>профиль контента</h2><div class='body'><table>
<tr><th>тип</th><th>файлов</th><th>размер</th><th>доля</th></tr>{kind_rows}</table></div></section>
<section><h2>находки</h2><div class='body'><table>
<tr><th style='width:90px'>уровень</th><th style='width:130px'>код</th><th>что</th><th style='width:50px'>шт</th></tr>{find_rows or "<tr><td colspan='4' class='faint'>пусто</td></tr>"}</table></div></section>
<section><h2>ассеты (первые 500)</h2><div class='body'><table>
<tr><th>путь</th><th>тип</th><th>размер</th><th>контейнер</th></tr>{assets_rows}</table></div></section>
<section><h2>сырые метаданные</h2><div class='body'><pre>{meta_json}</pre></div></section>
"""
    return page(f"salvage :: {ds.engine_name}", body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # тише в консоли
        pass

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path in ("/", "/index.html"):
                self._send(200, index_page())
            elif parsed.path == "/scan":
                raw = (qs.get("path") or [""])[0].strip()
                if not raw:
                    self._send(400, page("salvage", "<p>пустой путь</p><p><a href='/'>назад</a></p>"))
                    return
                p = Path(raw).expanduser()
                if not p.exists():
                    self._send(404, page("salvage", f"<p>нет такого пути: {_html.escape(raw)}</p><p><a href='/'>назад</a></p>"))
                    return
                engine = (qs.get("engine") or [""])[0]
                deep = (qs.get("deep") or ["0"])[0] == "1"
                self._send(200, result_page(p, engine, deep))
            else:
                self._send(404, page("salvage", "<p>404</p><p><a href='/'>назад</a></p>"))
        except Exception as exc:  # показываем ошибку в браузере, не роняем сервер
            self._send(500, page("salvage", f"<pre>{_html.escape(repr(exc))}</pre><p><a href='/'>назад</a></p>"))

    def _send(self, code: int, text: str) -> None:
        data = text.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="salvage.web")
    ap.add_argument("--port", type=int, default=8741)
    ap.add_argument("--host", default="127.0.0.1",
                    help="127.0.0.1 по умолчанию; 0.0.0.0 — только осознанно")
    ap.add_argument("--path", default="", help="предзаполнить путь")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"salvage web: http://{args.host}:{args.port}  (Ctrl+C — остановить)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
