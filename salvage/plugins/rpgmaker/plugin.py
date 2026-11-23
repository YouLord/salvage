"""RPG Maker-плагин: MV/MZ (шифрованные ассеты + System.json), XP/VX/VX Ace (RGSS-архивы).

Алгоритмы:
  MV/MZ: файл = 16-байтный фейк-заголовок ("RPGMV"/"RPGMZ" + нули) + данные,
         первые 16 байт данных = XOR с ключом encryptionKey из data/System.json.
  RGSSAD (XP): каждая папка/файл шифруется с инкрементным ключом на базе seed.
"""
from __future__ import annotations

import json
import re
import struct
from pathlib import Path

from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin
from ...core.util import classify, head_bytes, human_int, iter_files, rel_posix, safe_rel, sha256_file, sniff_magic
from .._shared import copy_verbatim, write_atomic

MV_FAKE = b"RPGMV"
MZ_FAKE = b"RPGMZ"
MV_EXT = {".rpgmvp": ".png", ".rpgmvo": ".ogg", ".rpgmvm": ".m4a", ".rpgmva": ".ogg",
          ".rpgmvc": ".ogg"}  # .rpgmvc — видео-обёртка в некоторых сборках
MZ_EXT = {".png_": ".png", ".ogg_": ".ogg", ".m4a_": ".m4a", ".webp_": ".webp",
          ".mp4_": ".mp4", ".oggvorbis_": ".ogg"}
RGSS_MAGIC = b"RGSSAD\x00"

_JSON_DB = {"Actors.json", "Classes.json", "Enemies.json", "Items.json", "Weapons.json",
            "Armors.json", "Skills.json", "States.json", "Troops.json", "MapInfos.json",
            "CommonEvents.json", "System.json", "Tilesets.json", "Animations.json",
            "Map%03d.json", "Quests.json"}


class RPGMakerPlugin(EnginePlugin):
    slug = "rpgmaker"
    display_name = "RPG Maker (MV/MZ/XP/VX/Ace)"
    can_extract = True
    notes = "MV/MZ: расчёт ключа и расшифровка; XP/VX/Ace: карта RGSS-архива."

    # ------------------------------------------------------------------
    def detect(self, root: Path) -> tuple[float, list[str]]:
        score = 0.0
        evidence: list[str] = []
        enc = rgss = system_json = plugins_js = data_json = 0
        for p in iter_files(root):
            ext = p.suffix.lower()
            name = p.name
            if ext in MV_EXT or ext in MZ_EXT:
                enc += 1
            elif name in ("System.json", "MapInfos.json", "Actors.json"):
                system_json += 1
                if system_json <= 2:
                    evidence.append(f"{name}: {rel_posix(p, root) if p.parent != root else p.name}")
            elif ext == ".js" and "rpg_" in p.parent.name.lower():
                plugins_js += 1
            elif ext == ".json" and name.endswith(".json") and re.match(r"Map\d{3}\.json", name):
                data_json += 1
            elif ext in (".rgssad", ".rgss2a", ".rgss3a"):
                rgss += 1
                evidence.append(f"RGSS-архив: {p.name}")
            head = head_bytes(p, 8)
            if head.startswith((MV_FAKE, MZ_FAKE)) and ext not in MV_EXT and ext not in MZ_EXT:
                enc += 1
                evidence.append(f"магия {head[:5].decode('latin-1')}: {p.name}")
            if score > 0.95:
                break
        if enc:
            score += min(0.6, 0.15 * enc)
            evidence.append(f"{enc} зашифрованных ассетов")
        if rgss:
            score += 0.7
        if system_json:
            score += 0.3
        if plugins_js:
            score += 0.25
            evidence.append(f"{plugins_js} файлов rpg_core/rpg_managers (MV/MZ)")
        if data_json:
            score += min(0.3, 0.02 * data_json)
        return min(score, 0.98), evidence[:8]

    # ------------------------------------------------------------------
    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        root_r = root.resolve()
        encrypted: list[Path] = []
        rgss: list[Path] = []
        jsons: dict[str, Path] = {}
        rxdata: list[Path] = []
        for p in iter_files(root, exclude=ctx.exclude):
            rel = rel_posix(p, root_r)
            try:
                size = p.stat().st_size
            except OSError:
                continue
            head = head_bytes(p, 8)
            magic = sniff_magic(head, rel)
            kind = classify(rel, magic)
            if p.suffix.lower() in MV_EXT or p.suffix.lower() in MZ_EXT:
                kind = "texture" if p.suffix.lower() in (".rpgmvp", ".png_", ".webp_") else "audio"
                if p.suffix.lower() in (".rpgmvm", ".m4a_", ".rpgmva", ".rpgmvc"):
                    kind = "video" if p.suffix.lower() == ".rpgmvc" else "audio"
            sha = sha256_file(p) if (ctx.hash_files and size <= ctx.hash_limit_mb << 20) else None
            a = ds.add_asset(rel, kind=kind, size=size, sha256=sha)
            if magic:
                a.extra["magic"] = magic
            ext = p.suffix.lower()
            if ext in MV_EXT:
                encrypted.append(p)
                a.extra["encrypted"] = "MV"
            elif ext in MZ_EXT:
                encrypted.append(p)
                a.extra["encrypted"] = "MZ"
            elif head.startswith((MV_FAKE, MZ_FAKE)):
                encrypted.append(p)
                a.extra["encrypted"] = "MV" if head.startswith(MV_FAKE) else "MZ"
            elif ext in (".rgssad", ".rgss2a", ".rgss3a"):
                rgss.append(p)
            elif ext in (".rxdata", ".rvdata", ".rvdata2"):
                rxdata.append(p)
            elif p.name in ("System.json", "MapInfos.json") or re.match(r"Map\d{3}\.json$", p.name):
                jsons[p.name] = p

        if "System.json" in jsons:
            self._read_system(ds, jsons["System.json"])
        elif encrypted:
            ds.add_finding(
                "warn", "rm_key_missing",
                "Зашифрованные ассеты есть, System.json не найден",
                "Ключ можно передать вручную: --rm-key <32 hex-символа> или --rm-key @System.json")
        for p in rgss:
            self._scan_rgss(ds, p, root_r)
        if rxdata:
            self._scan_data_files(ds, rxdata, root_r)
            ds.add_finding("info", "rm_data_files",
                           f"Файлов данных RPG Maker: {len(rxdata)}",
                           "Конвертация в JSON: salvage extract --data-json")
        if encrypted:
            ds.add_finding("info", "rm_encrypted",
                           f"Зашифровано MV/MZ-ассетов: {human_int(len(encrypted))}",
                           "Расшифровка выполняется при извлечении (это обратимая XOR-операция).")
        if ctx.deep:
            self._scan_databases(ds, jsons)
        return ds

    # ------------------------------------------------------------------
    def _read_system(self, ds: Dataset, path: Path) -> None:
        try:
            data = json.loads(path.read_text("utf-8", errors="ignore"))
        except (OSError, ValueError) as exc:
            ds.add_finding("warn", "rm_system_bad", f"System.json не читается: {exc}")
            return
        key_hex = data.get("encryptionKey") or ""
        key_hex = re.sub(r"[^0-9a-fA-F]", "", key_hex)[:32]
        ds.meta["rpgmaker"] = {
            "title": data.get("gameTitle"),
            "version_id": data.get("versionId"),
            "locale": data.get("locale"),
            "encryption_key_present": bool(key_hex),
            "encryption_key_masked": (key_hex[:6] + "…" + key_hex[-2:]) if key_hex else None,
        }
        if key_hex:
            ds.meta["_rm_key"] = key_hex

    # ------------------------------------------------------------------
    def _scan_data_files(self, ds: Dataset, files: list[Path], root_r: Path) -> None:
        ds.meta.setdefault("rpgmaker", {})["data_files"] = []
        for p in files[:5000]:
            rel = rel_posix(p, root_r)
            info = self._peek_marshal(p)
            ds.meta["rpgmaker"]["data_files"].append({"file": rel, **info})

    def _peek_marshal(self, path: Path) -> dict:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            return {"error": str(exc)}
        if not raw.startswith(b"\x04\x08"):
            return {"format": "не Marshal", "bytes": len(raw)}
        try:
            from ...core import ruby_marshal as rm
            obj = rm.loads(raw)
            kind = ("object" if isinstance(obj, rm.MRubyObj)
                    else "array" if isinstance(obj, list)
                    else "hash" if isinstance(obj, dict) else type(obj).__name__)
            size = len(obj) if isinstance(obj, (list, dict)) else (
                len(obj.ivars) if isinstance(obj, rm.MRubyObj) else 0)
            return {"format": "Marshal", "root": kind, "entries": size, "bytes": len(raw)}
        except Exception as exc:
            return {"format": "Marshal (не разобрался)", "error": str(exc), "bytes": len(raw)}

    def _scan_rgss(self, ds: Dataset, path: Path, root_r: Path) -> None:
        rel = rel_posix(path, root_r)
        try:
            with open(path, "rb") as f:
                head = f.read(8)
                if not head.startswith(b"RGSSAD"):
                    ds.add_finding("warn", "rgss_bad", f"{rel}: не RGSSAD", path=rel)
                    return
                version = head[7]
                f.seek(0)
                if version not in RGSS_LAYOUT:
                    ds.add_finding(
                        "warn", "rgss_unknown_version",
                        f"{rel}: неизвестная версия RGSSAD {version}",
                        "Известны 1 (XP/VX), 2 (патченный VX) и 3 (VX Ace); "
                        "разбор не выполняется, чтобы не выдать мусор за файлы.", path=rel)
                    return
                entries = parse_rgss_entries(f, version)
                if entries is None:
                    ds.add_finding("warn", "rgss_parse",
                                   f"{rel}: не удалось прочитать индекс (v{version})", path=rel)
                    return
                native = RGSS_NATIVE_VERSIONS.get(version, False)
                ds.meta.setdefault("rgss", []).append(
                    {"file": rel, "version": version, "entries": len(entries),
                     "native_version": native})
                if not native:
                    ds.add_finding(
                        "info", "rgss_version_patched",
                        f"{rel}: нестандартный байт версии {version}",
                        "Формат v2 не выпускался: это патченный VX-архив. "
                        "Читается схемой v1, как и оригинал.")
                ds.add_finding("info", "rgss_map",
                               f"{rel}: RGSSAD v{version}, файлов {human_int(len(entries))}",
                               "Извлечение и расшифровка выполняются при extract.", path=rel)
                for e in entries:
                    a = ds.add_asset(e["name"], kind=classify(e["name"]), size=e["size"],
                                     container=rel, rgss_offset=e["offset"],
                                     rgss_key=e["key"], rgss_version=version,
                                     rgss_size=e["size"])
                    a.extra["encrypted"] = True
        except (OSError, struct.error, ValueError) as exc:
            ds.add_finding("error", "rgss_io", f"{rel}: {exc}", path=rel)

    def _scan_databases(self, ds: Dataset, jsons: dict[str, Path]) -> None:
        maps = [n for n in jsons if n.startswith("Map") and n != "MapInfos.json"]
        ds.meta.setdefault("rpgmaker", {})["maps"] = len(maps)
        ids: set[int] = set()
        for name in maps:
            try:
                content = json.loads(jsons[name].read_text("utf-8", errors="ignore"))
            except (OSError, ValueError):
                continue
            if isinstance(content, list):
                for ev in content:
                    if isinstance(ev, dict) and isinstance(ev.get("id"), int):
                        ids.add(ev["id"])
        if maps:
            ds.add_finding("info", "rm_maps",
                           f"Карт: {len(maps)}, событий: {len(ids)}",
                           "Игровая логика в событиях карт и CommonEvents.json.")

    # ------------------------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        overwritten = 0
        base = copy_verbatim(dataset, dest, ctx, only_kinds)
        key = self._resolve_key(dataset, ctx)
        dec_dir = Path(dest) / "decrypted"
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        # Зашифрованные MV/MZ-ассеты — это только те, у которых есть маркер "encrypted",
        # а RGSS-архивы идут отдельным путём (см. ниже), поэтому не делаем early-return.
        encrypted = [a for a in dataset.assets if a.extra.get("encrypted")
                     and a.extra.get("encrypted") in ("MV", "MZ")]
        if not key and encrypted:
            out["message"] = ("Зашифрованные MV/MZ-ассеты пропущены: нет ключа. "
                              "Укажите --rm-key или положите System.json в data/.")
            out["skipped"] = len(encrypted)
        key_bytes = bytes.fromhex(key) if key else b""
        for a in (encrypted if key else []):
            if only_kinds and a.kind not in only_kinds:
                out["skipped"] += 1
                continue
            src = dataset.root / a.path
            if not src.is_file():
                out["skipped"] += 1
                continue
            try:
                data = src.read_bytes()
                dec = decrypt_mv(data, key_bytes)
                if dec is None:
                    out["errors"] += 1
                    continue
                # сохранить исходное имя файла и структуру папок
                stem = Path(a.path)
                tgt_name = dec_name(a.path)
                target = dec_dir / safe_rel(str(stem.parent / tgt_name))
                target.parent.mkdir(parents=True, exist_ok=True)
                overwritten += write_atomic(target, dec)
                out["extracted"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(str(target.relative_to(dec_dir)))
            except OSError as exc:
                out["errors"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(f"! {a.path}: {exc}")
        out["message"] = (f"MV/MZ: расшифровано {out['extracted']} файлов"
                          + (f", ошибок {out['errors']}" if out["errors"] else "") + ".")

        # --- RGSS архивы (XP/VX/Ace) ---
        rgss_sum = self._extract_rgss(dataset, dec_dir.parent, ctx, only_kinds)
        # --- конвертация данных (rxdata/rvdata2 → JSON) ---
        data_sum = {"extracted": 0, "errors": 0, "samples": [], "message": ""}
        if ctx.keys.get("data_json", "1") != "0":
            data_sum = self._extract_data_json(dataset, Path(dest), ctx, only_kinds)

        merged = dict(base)
        for k in ("extracted", "skipped", "errors"):
            merged[k] = base.get(k, 0) + out[k] + rgss_sum.get(k, 0) + data_sum.get(k, 0)
        merged["samples"] = (base.get("samples", []) + out["samples"]
                             + rgss_sum.get("samples", []) + data_sum.get("samples", []))[:20]
        msgs = [base["message"], out["message"], rgss_sum.get("message", ""),
                data_sum.get("message", "")]
        merged["message"] = " ".join(m for m in msgs if m).strip()
        return merged

    # ------------------------------------------------------------------
    def _extract_rgss(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                      only_kinds: set[str] | None) -> dict:
        overwritten = 0
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        for a in dataset.assets:
            if a.container is None or "rgss_version" not in a.extra:
                continue
            if only_kinds and a.kind not in only_kinds:
                out["skipped"] += 1
                continue
            src = dataset.root / a.container
            try:
                with open(src, "rb") as f:
                    data = extract_rgss_file(f, a.extra)
                if data is None:
                    out["errors"] += 1
                    continue
                target = Path(dest) / "rgss" / Path(a.container).stem / safe_rel(a.path)
                target.parent.mkdir(parents=True, exist_ok=True)
                overwritten += write_atomic(target, data[: ctx.max_asset_bytes])
                out["extracted"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(str(target.relative_to(Path(dest))))
            except (OSError, ValueError) as exc:
                out["errors"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(f"! {a.path}: {exc}")
        if out["extracted"] or out["errors"]:
            out["message"] = (f"RGSS: извлечено {out['extracted']} файлов"
                              + (f", ошибок {out['errors']}" if out["errors"] else "") + ".")
        return out

    # ------------------------------------------------------------------
    def _extract_data_json(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                           only_kinds: set[str] | None) -> dict:
        from ...core import ruby_marshal as rm

        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        if only_kinds and "data" not in only_kinds:
            return out
        for a in dataset.assets:
            low = a.path.lower()
            if not low.endswith((".rxdata", ".rvdata", ".rvdata2")) or a.container:
                continue
            src = dataset.root / a.path
            if not src.is_file():
                continue
            try:
                obj = rm.loads(src.read_bytes())
                target = dest / "data_json" / (safe_rel(a.path) + ".json")
                target.parent.mkdir(parents=True, exist_ok=True)
                import json as _json
                target.write_text(_json.dumps(rm.to_jsonable(obj), ensure_ascii=False,
                                              indent=1), encoding="utf-8")
                out["extracted"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(str(target.relative_to(dest)))
            except (OSError, ValueError, rm.MarshalError) as exc:
                out["errors"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(f"! {a.path}: {exc}")
        if out["extracted"]:
            out["message"] = f"Данные: {out['extracted']} файлов → JSON."
        return out

    def _resolve_key(self, dataset: Dataset, ctx: EngineContext) -> str | None:
        for k in ("rpgmaker", "rm_key", "rmmv"):
            v = ctx.keys.get(k)
            if v:
                return re.sub(r"[^0-9a-fA-F]", "", v)[:32]
        return dataset.meta.get("_rm_key")


# ---------------------------------------------------------------------------
# Алгоритмы
# ---------------------------------------------------------------------------

def decrypt_mv(data: bytes, key: bytes) -> bytes | None:
    """MV/MZ: отбросить 16-байтный фейк-заголовок, XOR первых 16 байт ключом."""
    if len(data) < 32:
        return None
    if data[:5] in (b"RPGMV", b"RPGMZ"):
        body = bytearray(data[16:])
    else:
        body = bytearray(data)
    for i in range(16):
        body[i] ^= key[i % len(key)]
    return bytes(body)


def dec_name(path: str) -> str:
    ext = Path(path).suffix.lower()
    for mapping in (MV_EXT, MZ_EXT):
        if ext in mapping:
            return Path(path).stem + mapping[ext]
    return Path(path).name


# ---------------------------------------------------------------------------
# RGSSAD v1 (XP/VX) и v3 (VX Ace)
#
# v1: заголовок 8 Б, далее записи:
#     [len u32 ^ key][имя, слова ^ key с key=key*7+3][size u32 ^ key][данные так же]
#     начальный key = 0xDEADCAFE
# v3: заголовок 8 Б, seed u32 => key = seed*9+3; индекс:
#     [offset][size][file_key][name_len] каждое ^ key (key НЕ ротируется),
#     имя ^ key по словам; данные каждого файла — свой file_key с ротацией *7+3.
# ---------------------------------------------------------------------------

MASK32 = 0xFFFFFFFF


def _u32(f) -> int:
    b = f.read(4)
    if len(b) < 4:
        raise ValueError("EOF")
    return struct.unpack("<I", b)[0]


def advance_key(key: int, words: int) -> int:
    """Перескок rolling-ключа key:=key*7+3 на words слов (мод 2^32).

    Использует геометрическую прогрессию, но ограничивает степень,
    чтобы не строить гигантские числа на испорченных данных.
    """
    if words <= 0:
        return key
    if words > 100_000:  # защита: такие «длины» — уже мусор/повреждение
        words = words % 100_000
    p = pow(7, words, 1 << 32)
    geom = ((7 ** 0 if words == 0 else pow(7, words) - 1) // 6) if words < 64 else 0
    if words < 64:
        return (p * key + 3 * geom) & MASK32
    # для больших words: (7^n - 1) / 6 mod 2^32 считаем через модуль 2^32 * 6
    geom = ((pow(7, words, (1 << 32) * 6) - 1) // 6) & MASK32
    return (p * key + 3 * geom) & MASK32


def decrypt_words(data: bytes, key: int, advance: bool = True) -> bytes:
    out = bytearray()
    k = key
    for i in range(0, len(data), 4):
        word = data[i:i + 4]
        w = int.from_bytes(word.ljust(4, b"\x00"), "little") ^ k
        out += w.to_bytes(4, "little")[:len(word)]
        if advance:
            k = (k * 7 + 3) & MASK32
    return bytes(out)


# Версии RGSS-архива. Сверено с эталонными реализациями (rpgo,
# RPGMakerDecrypter): самостоятельного формата версии 2 НЕ существует.
#   magic 1 — XP и VX: VX пишет тот же «RGSSAD\x00\x01», просто под именем
#             Game.rgss2a. Ключ 0xDEADCAFE, key = key*7+3 на каждое поле.
#   magic 2 — не стандарт; встречается у патченных сборок VX. Раскладка та же,
#             что в v1, поэтому читаем её как v1 и помечаем в отчёте.
#   magic 3 — VX Ace: другой заголовок (seed) и ключ на каждый файл.
#   прочее  — честная ошибка, а не «прочитали как получилось».
RGSS_LAYOUT = {1: "v1", 2: "v1", 3: "v3"}

# Какие версии объявляет сам движок (а какие — результат сторонних патчей)
RGSS_NATIVE_VERSIONS = {1: True, 2: False, 3: True}


def parse_rgss_entries(f, version: int) -> list[dict] | None:
    layout = RGSS_LAYOUT.get(version)
    if layout == "v1":
        return _parse_rgss_v1(f, version)
    if layout == "v3":
        return _parse_rgss_v3(f, version)
    return None


def _parse_rgss_v1(f, version: int) -> list[dict] | None:
    f.seek(8)
    entries: list[dict] = []
    if True:
        key = 0xDEADCAFE
        while True:
            b = f.read(4)
            if len(b) < 4:
                break
            name_len = struct.unpack("<I", b)[0] ^ key
            key = (key * 7 + 3) & MASK32
            if name_len <= 0 or name_len > 4096:
                break
            raw = f.read(name_len)
            if len(raw) < name_len:
                break
            name = decrypt_words(raw, key).decode("utf-8", "replace")
            key = advance_key(key, (name_len + 3) // 4)
            b = f.read(4)
            if len(b) < 4:
                break
            size = struct.unpack("<I", b)[0] ^ key
            key = (key * 7 + 3) & MASK32
            if size > 4 << 30:
                break
            offset = f.tell()
            entries.append({"name": name.replace("\\", "/"), "offset": offset,
                            "size": size, "key": key, "version": version})
            f.seek(size, 1)
            key = advance_key(key, (size + 3) // 4)
        return entries


def _parse_rgss_v3(f, version: int) -> list[dict] | None:
    f.seek(8)
    entries: list[dict] = []
    if True:
        seed = _u32(f)
        key = (seed * 9 + 3) & MASK32
        keybytes = key.to_bytes(4, "little")
        while True:
            head = f.read(16)
            if len(head) < 16:
                break
            offset = struct.unpack("<I", head[0:4])[0] ^ key
            if offset == 0:
                break
            size = struct.unpack("<I", head[4:8])[0] ^ key
            file_key = struct.unpack("<I", head[8:12])[0] ^ key
            name_len = struct.unpack("<I", head[12:16])[0] ^ key
            if name_len <= 0 or name_len > 4096:
                break
            if offset > 4 << 30 or size > 4 << 30:
                break
            raw = f.read(name_len)
            if len(raw) < name_len:
                break
            padded = (keybytes * ((name_len + 3) // 4))[:name_len]
            name = bytes(a ^ b for a, b in zip(raw, padded)).decode("utf-8", "replace")
            entries.append({"name": name.replace("\\", "/"), "offset": offset,
                            "size": size, "key": file_key, "version": version})
        return entries


def extract_rgss_file(f, extra: dict) -> bytes | None:
    """Прочитать и расшифровать один файл по данным индекса."""
    try:
        f.seek(extra["rgss_offset"])
        size = extra.get("rgss_size") or extra.get("size") or 0
        raw = f.read(size)
        return decrypt_words(raw, extra["rgss_key"])
    except (KeyError, OSError, ValueError):
        return None
