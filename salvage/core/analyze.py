"""Анализаторы поверх Dataset: дубликаты, битые ссылки, энтропия, секреты."""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from .model import Dataset
from .plugin_base import EngineContext
from .util import entropy_of_file, human_bytes, human_int

# ---------------------------------------------------------------------------
# 1. Дубликаты по sha256
# ---------------------------------------------------------------------------

ENCRYPTED_MAGICS = {"rpgmv", "rpgmz", "encrypted"}


def analyzer_duplicates(ds: Dataset, ctx: EngineContext) -> None:
    by_hash: dict[str, list] = defaultdict(list)
    for a in ds.assets:
        if a.sha256 and a.size > 0:
            by_hash[a.sha256].append(a)
    groups = [g for g in by_hash.values() if len(g) > 1]
    wasted = sum(g[0].size * (len(g) - 1) for g in groups)
    if not groups:
        ds.add_finding("ok", "no_dups", "Дубликатов по содержимому не найдено",
                       "sha256 всех файлов уникальны.")
        return
    examples = "; ".join(
        f"{g[0].path} ×{len(g)}" for g in sorted(groups, key=lambda g: -g[0].size)[:5]
    )
    ds.add_finding(
        "info", "dup_asset",
        f"Дубликаты: {len(groups)} групп, лишние копии занимают {human_bytes(wasted)}",
        f"Примеры: {examples}", count=len(groups),
    )
    ds.meta["duplicates"] = [
        {"sha256": h, "size": g[0].size, "copies": [a.path for a in g]}
        for h, g in sorted(by_hash.items(), key=lambda kv: -kv[1][0].size) if len(g) > 1
    ][:200]


# ---------------------------------------------------------------------------
# 2. Битые ссылки (deps → существующие пути)
# ---------------------------------------------------------------------------

def analyzer_broken_refs(ds: Dataset, ctx: EngineContext) -> None:
    if not ds.deps:
        return
    known = {a.path for a in ds.assets}
    known_lower = {p.lower() for p in known}
    # индексы по суффиксу для нечёткого сопоставления (common: "Assets/Foo/bar.png")
    by_base: dict[str, str] = {}
    for p in known:
        by_base.setdefault(p.rsplit("/", 1)[-1].lower(), p)

    broken: list[tuple[str, str]] = []
    for src, ref in ds.deps:
        if ref in known or ref.lower() in known_lower:
            continue
        base = ref.rsplit("/", 1)[-1].lower()
        if base in by_base:
            continue
        broken.append((src, ref))

    ds.meta["dependencies"] = len(ds.deps)
    if not broken:
        ds.add_finding("ok", "refs_ok",
                       f"Все ссылки разрешаются ({human_int(len(ds.deps))})")
        return
    uniq_targets = {r for _, r in broken}
    examples = "; ".join(f"{r} ← {s}" for s, r in broken[:5])
    ds.add_finding(
        "warn", "broken_ref",
        f"Битые ссылки: {len(broken)} (уникальных целей: {len(uniq_targets)})",
        f"Примеры: {examples}",
        count=len(broken),
    )
    ds.meta["broken_refs"] = [{"source": s, "target": r} for s, r in broken[:500]]


# ---------------------------------------------------------------------------
# 3. Энтропия: поиск зашифрованных/упакованных блобов
# ---------------------------------------------------------------------------

def analyzer_entropy(ds: Dataset, ctx: EngineContext) -> None:
    """Флагуем крупные файлы с энтропией > 7.5 бит/байт без известной магии."""
    root = ds.root
    suspicious = []
    checked = 0
    for a in ds.assets:
        if a.size < 64 * 1024 or a.container:
            continue
        if a.kind in ("archive", "binary") or a.extra.get("magic"):
            continue
        if ext_looks_compressed(a.path):
            continue
        p = root / a.path
        if not p.is_file():
            continue
        ent = entropy_of_file(p)
        checked += 1
        if ent >= 7.6:
            suspicious.append((a.path, ent))
        if checked > 3000:
            break
    if suspicious:
        ds.add_finding(
            "warn", "high_entropy",
            f"Высокая энтропия: {len(suspicious)} файлов — возможно шифрование",
            " ".join(f"{p} ({e:.2f})" for p, e in suspicious[:5]),
            count=len(suspicious),
        )
        ds.meta["high_entropy"] = [{"path": p, "entropy": round(e, 3)} for p, e in suspicious[:200]]


def ext_looks_compressed(name: str) -> bool:
    low = name.lower()
    return any(low.endswith(e) for e in
               (".png", ".jpg", ".jpeg", ".webp", ".ogg", ".mp3", ".m4a", ".zip",
                ".pck", ".pak", ".bundle", ".unity3d", ".rpa", ".gz", ".xz", ".zst"))


# ---------------------------------------------------------------------------
# 4. Инвентарь секретов / настроек в текстовых данных
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = [
    # \b перед \w не работает при camelCase (apiKey), поэтому граница задана явно
    ("api_key", re.compile(r"(?i)(?<![A-Za-z0-9])(api[_-]?key|apikey|secret[_-]?key)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]{12,})")),
    ("token", re.compile(r"(?i)\b(access[_-]?token|auth[_-]?token|bearer)\b\s*[:=]\s*['\"]?([A-Za-z0-9._\-]{16,})")),
    ("password", re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]([^'\"]{4,64})['\"]")),
    ("private_key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("keystore", re.compile(r"(?i)\b(keystore|storePassword|keyPassword|keyAlias)\b")),
    ("firebase_url", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("ip_addr", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("url", re.compile(r"https?://[^\s'\"<>)]{8,120}")),
]
_TEXT_EXT = (".json", ".xml", ".yml", ".yaml", ".ini", ".cfg", ".txt", ".bytes",
             ".js", ".cs", ".lua", ".gd", ".tsv", ".csv", ".plist", ".strings",
             ".gml", ".yy", ".asset", ".manifest", ".pck", ".mmap")


def analyzer_secrets(ds: Dataset, ctx: EngineContext) -> None:
    root = ds.root
    hits: dict[str, list[tuple[str, str]]] = defaultdict(list)
    scanned = 0
    for a in ds.assets:
        if a.container or a.size == 0 or a.size > 4 << 20:
            continue
        if not a.path.lower().endswith(_TEXT_EXT):
            continue
        p = root / a.path
        try:
            text = p.read_text("utf-8", errors="ignore")
        except OSError:
            continue
        scanned += 1
        # для URL/ip — только в «интересных» файлах, чтобы не шуметь на локализации
        interesting = any(w in a.path.lower() for w in
                          ("config", "settings", "system", "manifest", "build", "env",
                           "network", "server", "app", "game", "gradle", "project", "data"))
        for name, rx in _SECRET_PATTERNS:
            if name in ("url", "ip_addr", "keystore") and not interesting:
                continue
            for m in rx.finditer(text):
                if m.lastindex and m.lastindex >= 2:
                    sample = m.group(m.lastindex)  # значение (последняя группа)
                elif m.lastindex == 1:
                    sample = m.group(1)
                else:
                    sample = m.group(0)
                hits[name].append((a.path, sample[:160]))
                if len(hits[name]) > 200:
                    break
        if scanned > 4000:
            break

    if hits:
        summary = ", ".join(f"{k}: {len(v)}" for k, v in sorted(hits.items()))
        ds.add_finding(
            "info", "secrets_inventory",
            "Инвентарь потенциально чувствительных строк",
            summary + ". Только для аудита — ничего не публикуйте.",
            count=sum(len(v) for v in hits.values()),
        )
        ds.meta["secrets"] = {k: [{"path": p, "match": m} for p, m in v[:50]]
                             for k, v in hits.items()}


# ---------------------------------------------------------------------------
# 5. Крупнейшие файлы (для карты веса)
# ---------------------------------------------------------------------------

def analyzer_biggest(ds: Dataset, ctx: EngineContext) -> None:
    if not ds.assets:
        return
    top = ds.biggest(10)
    ds.meta["biggest"] = [{"path": a.path, "bytes": a.size} for a in top]


ANALYZERS = [analyzer_duplicates, analyzer_broken_refs, analyzer_entropy,
             analyzer_secrets, analyzer_biggest]


def run_analyzers(ds: Dataset, ctx: EngineContext) -> None:
    for fn in ANALYZERS:
        try:
            fn(ds, ctx)
        except Exception as exc:  # анализ не должен ронять скан
            ds.scan_errors.append(f"analyzer {fn.__name__}: {exc}")
