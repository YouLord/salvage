"""Doctor Mode: отчёт о «здоровье» проекта — как renpy doctor, но для любой игры.

Проверки:
  * целостность медиа: битые заголовки картинок/звука, нулевые файлы,
    подозрительные размеры;
  * связанность: ссылки из сцен/скриптов на отсутствующие ассеты;
  * дубликаты и вес;
  * зашифрованные/запакованные блоки, которые инструмент не прочитал;
  * «пустые комнаты»: контейнеры без извлечённого контента.

Вход: Dataset (после scan). Выход: структура для HTML/JSON + CLI-текст.
"""
from __future__ import annotations

import struct
from pathlib import Path

from ..core.model import Dataset
from ..core.util import human_bytes, human_int

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
JPG_MAGIC = b"\xff\xd8\xff"
GIF_MAGIC = b"GIF8"
OGG_MAGIC = b"OggS"
WAV_MAGIC = b"RIFF"
MP3_MAGIC = (b"ID3", b"\xff\xfb", b"\xff\xf3")
WEBP_MAGIC = b"RIFF"


def _head(path: Path, n: int = 16) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def check_media(ds: Dataset) -> dict:
    """Проверка заголовков медиа: битые PNG/JPEG/OGG и нулевые файлы."""
    bad_images: list[dict] = []
    bad_audio: list[dict] = []
    empty: list[str] = []
    checked = 0
    for a in ds.assets:
        if a.container:
            # контент контейнеров (RPA/PCK/PAK) проверяется при извлечении, не на диске
            continue
        low = a.path.lower()
        is_img = low.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif"))
        is_aud = low.endswith((".ogg", ".wav", ".mp3", ".m4a"))
        if not (is_img or is_aud):
            continue
        p = ds.root / a.path
        if not p.is_file():
            continue
        checked += 1
        size = p.stat().st_size
        if size == 0:
            empty.append(a.path)
            continue
        head = _head(p, 16)
        if is_img:
            ok = (head.startswith(PNG_MAGIC) or head.startswith(JPG_MAGIC)
                  or head.startswith(GIF_MAGIC) or head.startswith(WEBP_MAGIC))
            if not ok:
                # PNG может быть внутри BZ2 (GM) — проверяем BZh
                if head[:3] != b"BZh":
                    bad_images.append({"path": a.path, "head": head[:8].hex()})
        else:
            ok = (head.startswith(OGG_MAGIC) or head.startswith(WAV_MAGIC)
                  or any(head.startswith(m) for m in MP3_MAGIC))
            if not ok and head[:3] != b"BZh":
                bad_audio.append({"path": a.path, "head": head[:8].hex()})
        if checked > 20000:
            break
    return {"checked": checked, "bad_images": bad_images[:200],
            "bad_audio": bad_audio[:200], "empty": empty[:200],
            "counts": {"bad_images": len(bad_images), "bad_audio": len(bad_audio),
                       "empty": len(empty)}}


def check_png_dimensions(ds: Dataset) -> list[dict]:
    """Найти PNG с нулевыми/огромными размерами (частая порча при моддинге)."""
    out = []
    count = 0
    for a in ds.assets:
        if a.container or not a.path.lower().endswith(".png"):
            continue
        p = ds.root / a.path
        try:
            with open(p, "rb") as f:
                head = f.read(33)
        except OSError:
            continue
        if len(head) < 33 or not head.startswith(PNG_MAGIC):
            continue
        w, h = struct.unpack(">II", head[16:24])
        if w == 0 or h == 0 or w > 32768 or h > 32768:
            out.append({"path": a.path, "width": w, "height": h})
        count += 1
        if count > 20000:
            break
    return out


def check_containers(ds: Dataset) -> dict:
    """Контейнеры, из которых не извлеклось ничего (пустые/непрочитанные)."""
    containers: dict[str, int] = {}
    for a in ds.assets:
        if a.container:
            containers[a.container] = containers.get(a.container, 0) + 1
    empty = []
    for a in ds.assets:
        if a.kind not in ("archive",) or a.container:
            continue
        if a.path in containers:
            continue
        low = a.path.lower()
        if low.endswith((".pak", ".pck", ".rpa", ".rgssad", ".rgss3a", ".win",
                         ".bundle", ".unity3d", ".assets")):
            # .win/.fsb и т.п. разбираются движковыми плагинами без создания
            # дочерних «ассетов-контейнеров» — не считаем их пустыми
            if low.endswith((".win", ".fsb", ".bank", ".dat")):
                continue
            empty.append(a.path)
    return {"total": len(containers), "empty": empty[:200],
            "counts": {"empty": len(empty)}}


def run_doctor(ds: Dataset) -> dict:
    """Сводный «врачебный» отчёт."""
    media = check_media(ds)
    pngs = check_png_dimensions(ds)
    containers = check_containers(ds)
    by = ds.findings_by_severity()

    score = 100
    # PNG с нулевыми размерами — тоже битые (просто заголовок валиден)
    zero_dim_pngs = [p for p in pngs if p["width"] == 0 or p["height"] == 0]
    score -= min(30, (media["counts"]["bad_images"] + len(zero_dim_pngs)) * 2)
    score -= min(20, media["counts"]["bad_audio"] * 2)
    score -= min(10, media["counts"]["empty"] * 2)
    score -= min(15, len(pngs) * 2)
    score -= min(15, containers["counts"]["empty"] * 3)
    score -= min(10, len(by["error"]) * 2)
    score -= min(10, len(by["warn"]))
    score = max(0, score)

    verdict = ("отлично" if score >= 90 else
               "хорошо" if score >= 75 else
               "требует внимания" if score >= 50 else "проблемный проект")

    return {
        "score": score,
        "verdict": verdict,
        "engine": ds.engine_name,
        "totals": {"files": ds.total_files, "bytes": ds.total_size},
        "media": media,
        "pngs": pngs[:200],
        "containers": containers,
        "findings": {"error": len(by["error"]), "warn": len(by["warn"]),
                     "info": len(by["info"])},
    }


def doctor_markdown(report: dict) -> str:
    m = report["media"]
    lines = [
        f"# Врачебный отчёт: {report['engine']}",
        "",
        f"**Оценка здоровья: {report['score']}/100 — {report['verdict']}**",
        "",
        f"- файлов: {human_int(report['totals']['files'])} "
        f"({human_bytes(report['totals']['bytes'])})",
        f"- проверено медиа: {human_int(m['checked'])}",
        f"- битые изображения: {m['counts']['bad_images']}",
        f"- битые аудио: {m['counts']['bad_audio']}",
        f"- пустые файлы: {m['counts']['empty']}",
        f"- аномальные PNG: {len(report['pngs'])}",
        f"- контейнеры без содержимого: {report['containers']['counts']['empty']}",
        f"- находки: ошибки {report['findings']['error']}, "
        f"предупреждения {report['findings']['warn']}",
        "",
    ]
    if m["bad_images"]:
        lines.append("## Битые изображения")
        lines += [f"- `{x['path']}` (первые байты: {x['head']})" for x in m["bad_images"][:30]]
        lines.append("")
    if m["bad_audio"]:
        lines.append("## Битые аудио")
        lines += [f"- `{x['path']}` (первые байты: {x['head']})" for x in m["bad_audio"][:30]]
        lines.append("")
    if report["pngs"]:
        lines.append("## Аномальные PNG")
        lines += [f"- `{x['path']}` — {x['width']}×{x['height']}" for x in report["pngs"][:30]]
        lines.append("")
    if report["containers"]["empty"]:
        lines.append("## Контейнеры без прочитанного содержимого")
        lines += [f"- `{p}`" for p in report["containers"]["empty"][:30]]
        lines.append("")
    return "\n".join(lines) + "\n"
