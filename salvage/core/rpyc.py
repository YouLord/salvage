"""Разбор и «мягкая» декомпиляция скомпилированных Ren'Py-скриптов (.rpyc).

Формат (Ren'Py ≥ 6.99.5, «RPC2»):
    b"RENPY RPC2" + таблица слотов [slot u32][start u32][length u32]*, slot=0 — конец.
    Слот 1 — zlib-сжатый pickle AST; слот 2 — то же с применёнными трансформациями.

Мы не исполняем pickle: свой минимальный анализатор opcode'ов извлекает:
  * строковые константы (диалоги/экраны),
  * имена файлов/меток,
  * структуру блоков по классам renpy.ast.*,
  * и рендерит приближённый .rpy-текст (say/dialogue/меню/menu).
Полная точная декомпиляция (как в unrpyc) требует эмуляции всех классов
Ren'Py — это вынесено в roadmap, но для аудита и поиска конфигов этого достаточно.
"""
from __future__ import annotations

import io
import pickle
import re
import zlib
from pathlib import Path

RPYC_MAGIC = b"RENPY RPC2"


class RpycError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Чтение контейнера
# ---------------------------------------------------------------------------

def parse_rpc2(raw: bytes) -> dict[int, bytes]:
    """Вернуть слоты {slot: bytes} из RPC2-контейнера."""
    if not raw.startswith(RPYC_MAGIC):
        # старый формат (< 6.99.5) — просто zlib-поток
        return {1: raw}
    pos = 10
    slots: dict[int, bytes] = {}
    while pos + 12 <= len(raw):
        slot, start, length = int.from_bytes(raw[pos:pos + 4], "little"), \
            int.from_bytes(raw[pos + 4:pos + 8], "little"), \
            int.from_bytes(raw[pos + 8:pos + 12], "little")
        if slot == 0:
            break
        pos += 12
        if start < len(raw) and start + length <= len(raw):
            slots[slot] = raw[start:start + length]
    return slots


def decompress_slot(data: bytes) -> bytes:
    """zlib-распаковка (RPC2-слот или «голый» старый .rpyc)."""
    try:
        return zlib.decompress(data)
    except zlib.error as exc:
        raise RpycError(f"zlib: {exc}") from exc


def open_ast(raw: bytes) -> bytes:
    """Получить распакованный pickle AST из любого варианта .rpyc."""
    if raw.startswith(RPYC_MAGIC):
        slots = parse_rpc2(raw)
        if 1 not in slots:
            raise RpycError("нет слота 1 (AST) в RPC2")
        return decompress_slot(slots[1])
    # fallback: файл целиком — zlib-поток с pickle
    return decompress_slot(raw)


# ---------------------------------------------------------------------------
# Минимальный безопасный разбор pickle (без импорта классов)
# ---------------------------------------------------------------------------

class Node:
    """Универсальный «безопасный» узел AST: атрибуты, но без поведения."""

    def __init__(self, *args, **kwargs):
        kind = kwargs.pop("_salvage_kind", "?")
        self._kind = kind

    def __setstate__(self, state):
        # ВАЖНО: pickle для NEWOBJ+BUILD вызывает __setstate__ даже когда его нет
        # (через object.__reduce_ex__), поэтому маркер _kind надо восстановить.
        kind = self.__dict__.get("_kind")
        if kind is None:
            cls = type(self)
            if getattr(cls, "__module__", "").startswith("renpy"):
                kind = f"{cls.__module__}.{cls.__name__}"
                self.__dict__["_kind"] = kind
        if isinstance(state, dict):
            self.__dict__.update(state)
        elif isinstance(state, tuple) and len(state) == 2 and isinstance(state[1], dict):
            self.__dict__.update(state[1])

    def __repr__(self):
        return f"<{self._kind}>"


_CLASS_CACHE: dict[tuple[str, str], type] = {}


def _make_class(module: str, name: str):
    """Класс-заглушка. Кэшируется и регистрируется в модуле, чтобы pickle
    мог найти его по имени (иначе 'Can't get local object')."""
    key = (module, name)
    if key in _CLASS_CACHE:
        return _CLASS_CACHE[key]
    kind = f"{module}.{name}"

    class NodeStub(Node):
        def __init__(self, *args, **kwargs):
            Node.__init__(self)
            self.__dict__["_kind"] = kind   # а не self._kind: избегаем __setattr__-ловушек
            self.__dict__["_args"] = args

    NodeStub.__name__ = name
    NodeStub.__module__ = module
    NodeStub.__qualname__ = name
    _CLASS_CACHE[key] = NodeStub
    return NodeStub


class _MiniUnpickler(pickle.Unpickler):
    """Ничего не импортирует из renpy: все классы — безопасные заглушки."""

    def find_class(self, module, name):
        if module == "builtins":
            return super().find_class(module, name)
        return _make_class(module, name)

    def persistent_load(self, pid):
        return {"__persistent__": str(pid)}


def load_nodes(data: bytes):
    bio = io.BytesIO(data)
    try:
        return _MiniUnpickler(bio, encoding="utf-8", errors="surrogateescape").load()
    except Exception as exc:
        raise RpycError(f"pickle: {exc}") from exc


# ---------------------------------------------------------------------------
# Обход AST
# ---------------------------------------------------------------------------

def iter_nodes(obj, depth: int = 0):
    """Ленивый обход: выдаёт все Node-объекты (в т.ч. вложенные в списки/поля)."""
    if depth > 96:
        return
    if isinstance(obj, Node):
        yield obj
        for v in list(getattr(obj, "__dict__", {}).values()):
            yield from iter_nodes(v, depth + 1)
        for v in getattr(obj, "_args", ()):
            yield from iter_nodes(v, depth + 1)
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from iter_nodes(v, depth + 1)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from iter_nodes(v, depth + 1)


def iter_strings(obj, depth: int = 0):
    if depth > 96:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, Node):
        for v in list(getattr(obj, "__dict__", {}).values()):
            yield from iter_strings(v, depth + 1)
        for v in getattr(obj, "_args", ()):
            yield from iter_strings(v, depth + 1)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str):
                yield k
            yield from iter_strings(v, depth + 1)
    elif isinstance(obj, (list, tuple, set)):
        for v in obj:
            yield from iter_strings(v, depth + 1)


def collect_strings(ast) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for s in iter_strings(ast):
        s = s.strip()
        if len(s) < 2 or s in seen:
            continue
        if s.startswith("__") or s.startswith("renpy."):
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= 20000:
            break
    return out


def _first_str(*candidates) -> str | None:
    for c in candidates:
        if isinstance(c, str) and c:
            return c
    return None


def extract_elements(ast) -> dict:
    """Достать из AST метки, экраны, персонажей и реплики (эвристика по классам)."""
    info = {"labels": [], "screens": [], "characters": [], "dialogue": []}
    for n in iter_nodes(ast):
        kind = getattr(n, "_kind", "")
        short = kind.rsplit(".", 1)[-1]
        d = getattr(n, "__dict__", {})
        if short == "Label":
            name = _first_str(d.get("name"), d.get("label_name"))
            if name:
                info["labels"].append(name)
        elif short == "Screen":
            name = _first_str(d.get("screen_name"), d.get("name"))
            if name:
                info["screens"].append(name)
        elif short in ("Say", "TranslateSay", "Translate"):
            who = _first_str(d.get("who"), d.get("who_what"))
            what = _first_str(d.get("what"), d.get("translation"))
            if what:
                info["dialogue"].append({"who": who or "", "what": what[:500]})
        elif short in ("Menu", "Choice"):
            pass
        # персонажи: define-объекты хранятся в Character(), встречаются как строки-имена
        if "Character" in short:
            name = _first_str(d.get("name"), d.get("display_name"))
            if name:
                info["characters"].append(name)
    for k in ("labels", "screens", "characters"):
        info[k] = sorted(set(info[k]))[:1000]
    info["dialogue"] = info["dialogue"][:5000]
    return info


def render_partial_rpy(ast, strings: list[str], info: dict | None = None) -> str:
    """Приближённый .rpy: метки, экраны, реплики и текстовые константы."""
    info = info or extract_elements(ast)
    lines = [
        "# salvaged by salvage — приближённая реконструкция",
        "# источник: .rpyc (RPC2). Точные операторы не восстанавливались;",
        "# сохранены метки, экраны, персонажи и реплики (для аудита).",
        "",
    ]
    if info["characters"]:
        lines.append("# персонажи: " + ", ".join(info["characters"][:40]))
    if info["screens"]:
        lines.append("# экраны: " + ", ".join(info["screens"][:40]))
    lines.append("")
    labels = info["labels"] or ["__unknown__"]
    for lab in labels:
        lines.append(f"label {lab}:")
    for d in info["dialogue"]:
        who = d["who"] or ""
        what = d["what"].replace("\n", "\\n").replace('"', '\\"')
        if who:
            lines.append(f'    {who} "{what}"')
        else:
            lines.append(f'    "{what}"')
    if info["dialogue"]:
        lines.append("    return")
    lines.append("")
    lines.append("# --- все строковые константы ---")
    for s in strings[:5000]:
        s2 = s.replace("\n", "\\n")
        if len(s2) > 240:
            s2 = s2[:237] + "..."
        lines.append(f"# {s2}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Высокоуровневый API
# ---------------------------------------------------------------------------

def decompile_file(path: Path, out_path: Path | None = None,
                   full: bool = False) -> dict:
    """Разобрать .rpyc; при out_path — записать реконструкцию/строки."""
    raw = path.read_bytes()
    ast = load_nodes(open_ast(raw))
    strings = collect_strings(ast)
    info = extract_elements(ast)
    result = {"file": str(path), "strings": len(strings),
              "labels": len(info["labels"]), "screens": len(info["screens"]),
              "dialogue": len(info["dialogue"]),
              "container": "RPC2" if raw.startswith(RPYC_MAGIC) else "legacy"}
    if out_path:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        if full:
            out_path.write_text(render_partial_rpy(ast, strings, info), encoding="utf-8")
        else:
            out_path.write_text("\n".join(strings), encoding="utf-8")
        result["written"] = str(out_path)
    return result
