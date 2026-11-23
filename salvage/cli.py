"""CLI: argparse-пульт (без зависимостей), ASCII-таблица отчёта, коды возврата.

Коды возврата (для CI):
  0 — всё чисто или только info
  1 — выявлены предупреждения
  2 — выявлены ошибки
  3 — ошибка выполнения
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .core.model import SEVERITY_ORDER, SEVERITY_TITLES
from .core.plugin_base import EngineContext
from .core.registry import build_registry
from .core.scan import ScanError, scan
from .core.util import KIND_LABELS_RU, human_bytes, human_int
from .report.export import write_json, write_markdown, export_json_text
from .report.html import write_html


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="salvage",
        description="salvage — аудит и восстановление ассетов игр "
                    "(Unity, Godot, GameMaker, RPG Maker, Ren'Py + generic).",
    )
    ap.add_argument("--version", action="version", version=f"salvage {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("path", help="каталог игры или проекта")
        sp.add_argument("--engine", default=None,
                        choices=sorted(build_registry()),
                        metavar="ENGINE",
                        help="форсировать движок: " + ", ".join(sorted(build_registry()))
                             + " (без флага — автодетект, generic — запасной)")
        sp.add_argument("--deep", action="store_true",
                        help="глубокий скан: разбор контейнеров, зависимости")
        sp.add_argument("--no-hash", action="store_true", help="не считать sha256")
        sp.add_argument("--exclude", action="append", default=[], metavar="DIR",
                        help="исключить каталог (можно несколько)")

    sp_scan = sub.add_parser("scan", help="аудит без извлечения")
    common(sp_scan)
    sp_scan.add_argument("--out", default="salvage-report", help="каталог отчёта")
    sp_scan.add_argument("--formats", default="html,json,md",
                         help="форматы через запятую: html,json,md")
    sp_scan.add_argument("--max-seconds", type=int, default=0,
                         help="мягкий лимит времени (0 — без лимита; сейчас информативно)")
    sp_scan.add_argument("--doctor", action="store_true",
                         help="включить врачебный отчёт (медиа, ссылки, контейнеры)")

    sp_x = sub.add_parser("extract", help="извлечь ассеты в каталог")
    common(sp_x)
    sp_x.add_argument("--out", required=True, help="каталог для извлечённых ассетов")
    sp_x.add_argument("--kinds", default="",
                      help="только эти типы (texture,audio,data,...), через запятую")
    sp_x.add_argument("--report", action="store_true", help="дополнительно построить отчёт")
    sp_x.add_argument("--rm-key", default=None,
                      help="ключ RPG Maker MV/MZ: 32 hex-символа или @путь/к/System.json")
    sp_x.add_argument("--texture-format", default="png", choices=["png", "qoi", "bz2", "both"],
                      help="формат текстурных страниц GameMaker (png/qoi/bz2/both)")
    sp_x.add_argument("--data-json", action="store_true", default=True,
                      help="конвертировать rxdata/rvdata2 в JSON (по умолчанию вкл.)")
    sp_x.add_argument("--no-data-json", dest="data_json", action="store_false",
                      help="не конвертировать данные RPG Maker")
    sp_x.add_argument("--rpyc-full", action="store_true", default=True,
                      help="декомпилировать .rpyc в приближённый .rpy (по умолчанию)")
    sp_x.add_argument("--rpyc-strings", dest="rpyc_full", action="store_false",
                      help="только извлекать строки из .rpyc")
    sp_x.add_argument("--max-asset-bytes", type=int, default=16 << 20,
                      help="лимит одного извлекаемого файла, байт (по умолчанию 16 МиБ)")

    sp_a = sub.add_parser("audit", help="scan + отчёт одной командой (по умолчанию html+json+md)")
    common(sp_a)
    sp_a.add_argument("--out", default="salvage-report")
    sp_a.add_argument("--formats", default="html,json,md",
                      help="форматы через запятую: html,json,md")
    sp_a.add_argument("--doctor", action="store_true", default=True,
                      help="врачебный отчёт (по умолчанию включён)")
    sp_a.add_argument("--no-doctor", dest="doctor", action="store_false")

    sp_d = sub.add_parser("detect", help="только определить движок")
    sp_d.add_argument("path")

    sp_l = sub.add_parser("engines", help="список подключённых движков")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "engines":
            return _cmd_engines()
        if args.cmd == "detect":
            return _cmd_detect(Path(args.path))
        if args.cmd == "audit" and not hasattr(args, "doctor"):
            args.doctor = True
        if args.cmd in ("scan", "audit"):
            return _cmd_scan(args)
        if args.cmd == "extract":
            return _cmd_extract(args)
    except ScanError as exc:
        print(f"salvage: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\nsalvage: прервано пользователем", file=sys.stderr)
        return 3
    return 0


# ---------------------------------------------------------------------------

def _ctx_from_args(args) -> EngineContext:
    return EngineContext(
        deep=args.deep,
        hash_files=not args.no_hash,
        max_asset_bytes=getattr(args, "max_asset_bytes", 16 << 20),
        exclude=[Path(p) for p in args.exclude],
    )


def _cmd_engines() -> int:
    reg = build_registry()
    print("Движок        slug          извлечение  описание")
    print("-" * 78)
    for slug, plugin in reg.items():
        ex = "да" if plugin.can_extract else "нет"
        print(f"{plugin.display_name:<14}{slug:<14}{ex:<11}{plugin.notes}")
    return 0


def _cmd_detect(path: Path) -> int:
    from .core.registry import detect_all
    if not path.exists():
        print(f"salvage: нет такого пути: {path}", file=sys.stderr)
        return 3
    hits = detect_all(path)
    if not hits:
        print("Движок не распознан — будет использован generic.")
        return 0
    print(f"Кандидаты для {path}:")
    for plugin, score, evidence in hits[:5]:
        print(f"  {plugin.display_name:<12} {score:.2f}  {'; '.join(evidence[:3])}")
    return 0


def _cmd_scan(args) -> int:
    ctx = _ctx_from_args(args)
    ds, plugin = scan(Path(args.path), args.engine, ctx)
    _print_summary(ds)
    if getattr(args, "doctor", False):
        from .core.doctor import run_doctor
        ds.meta["doctor"] = run_doctor(ds)
        _print_doctor(ds.meta["doctor"])
    out = Path(args.out)
    formats = {f.strip().lower() for f in args.formats.split(",") if f.strip()}
    written = []
    if "html" in formats:
        written.append(write_html(ds, out / "report.html"))
    if "json" in formats:
        written.append(write_json(ds, out / "scan.json"))
    if "md" in formats:
        written.append(write_markdown(ds, out / "report.md"))
    for w in written:
        print(f"  отчёт: {w}")
    return _exit_code(ds)


def _cmd_extract(args) -> int:
    ctx = _ctx_from_args(args)
    if args.rm_key:
        key = args.rm_key
        if key.startswith("@"):
            import json as _json
            try:
                syst = _json.loads(Path(key[1:]).read_text("utf-8", errors="ignore"))
                key = syst.get("encryptionKey", "")
            except (OSError, ValueError) as exc:
                print(f"salvage: не удалось прочитать ключ из {key[1:]}: {exc}", file=sys.stderr)
                return 3
        ctx.keys["rpgmaker"] = key
    ctx.keys["texture_format"] = args.texture_format
    ctx.keys["data_json"] = "1" if args.data_json else "0"
    ctx.keys["rpyc_full"] = "1" if args.rpyc_full else "0"
    ds, plugin = scan(Path(args.path), args.engine, ctx)
    _print_summary(ds)
    kinds = {k.strip().lower() for k in args.kinds.split(",") if k.strip()} or None
    dest = Path(args.out)
    dest.mkdir(parents=True, exist_ok=True)
    summary = plugin.extract(ds, dest, ctx, kinds)
    ds.extracted_count = summary.get("extracted", 0)
    ds.extraction = {k: v for k, v in summary.items() if k != "samples"}
    print()
    print(f"Извлечение в {dest}:")
    print(f"  файлов: {summary.get('extracted', 0)}  пропущено: {summary.get('skipped', 0)}"
          f"  ошибок: {summary.get('errors', 0)}")
    if summary.get("message"):
        print(f"  {summary['message']}")
    for s in (summary.get("samples") or [])[:10]:
        print(f"    · {s}")
    if args.report:
        out = dest / "_report"
        write_html(ds, out / "report.html")
        write_json(ds, out / "scan.json")
        print(f"  отчёт: {out / 'report.html'}")
    return _exit_code(ds)


def _exit_code(ds) -> int:
    by = ds.findings_by_severity()
    if by["error"]:
        return 2
    if by["warn"]:
        return 1
    return 0


def _print_doctor(rep: dict) -> None:
    m = rep["media"]["counts"]
    print()
    print(f"DOCTOR // здоровье {rep['score']}/100 — {rep['verdict']}")
    print(f"  медиа проверено: {human_int(rep['media']['checked'])}"
          f" · битых картинок: {m['bad_images']} · битых звуков: {m['bad_audio']}"
          f" · пустых: {m['empty']}")
    if rep["pngs"]:
        print(f"  аномальных PNG: {len(rep['pngs'])}")
    if rep["containers"]["counts"]["empty"]:
        print(f"  контейнеров без содержимого: {rep['containers']['counts']['empty']}")


# ---------------------------------------------------------------------------
# ASCII-сводка в терминал
# ---------------------------------------------------------------------------

def _print_summary(ds) -> None:
    print()
    print(f"SALVAGE // {ds.engine_name} @ {ds.root}")
    print("=" * 78)
    print(f"  файлов: {human_int(ds.total_files):>10}   объём: {human_bytes(ds.total_size):>10}")
    print(f"  движок: {ds.engine_slug:<12} уверенность: {ds.score:.2f}")
    kinds = ds.kind_stats()
    if kinds:
        print("  профиль:")
        for kind, (cnt, size) in list(kinds.items())[:8]:
            label = KIND_LABELS_RU.get(kind, kind)
            print(f"    {label:<16} {human_int(cnt):>8} файлов  {human_bytes(size):>10}")
    by = ds.findings_by_severity()
    total = sum(len(v) for v in by.values())
    if total:
        print("  находки:")
        for sev in ("error", "warn", "info", "ok"):
            for f in by.get(sev, [])[:12]:
                print(f"    [{SEVERITY_TITLES[sev]:<8}] {f.title}")
        hidden = total - sum(min(len(by.get(s, [])), 12) for s in by)
        if hidden > 0:
            print(f"    … ещё {hidden} (полный список — в отчёте)")
    print("=" * 78)


if __name__ == "__main__":
    raise SystemExit(main())
