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
from .._shared import copy_verbatim

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
    def _scan_rgss(self, ds: Dataset, path: Path, root_r: Path) -> None:
        rel = rel_posix(path, root_r)
        try:
            with open(path, "rb") as f:
                head = f.read(8)
                if head != RGSS_MAGIC:
                    ds.add_finding("warn", "rgss_bad", f"{rel}: не RGSSAD", path=rel)
                    return
                version = struct.unpack("<I", f.read(4))[0]
                ds.meta.setdefault("rgss", []).append({"file": rel, "version": version})
                if version == 1:
                    ds.add_finding("info", "rgss_v1",
                                   f"{rel}: RGSSAD v1 (RPG Maker XP)",
                                   "Индекс зашифрован инкрементным ключом — поддержка в roadmap "
                                   "(extract пока копирует архив целиком).", path=rel)
                elif version == 3:
                    ds.add_finding("info", "rgss_v3",
                                   f"{rel}: RGSS3A v3 (RPG Maker VX Ace)",
                                   "Файлы доступны только с ключом — поддержка в roadmap.", path=rel)
                else:
                    ds.add_finding("info", "rgss_ver",
                                   f"{rel}: RGSSAD v{version}", path=rel)
        except OSError as exc:
            ds.add_finding("error", "rgss_io", f"{rel}: {exc}", path=rel)

    # ------------------------------------------------------------------
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
        base = copy_verbatim(dataset, dest, ctx, only_kinds)
        key = self._resolve_key(dataset, ctx)
        dec_dir = Path(dest) / "decrypted"
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        encrypted = [a for a in dataset.assets if a.extra.get("encrypted")]
        if not encrypted:
            return base
        if not key:
            out["message"] = ("Зашифрованные ассеты пропущены: нет ключа. "
                              "Укажите --rm-key или положите System.json в data/.")
            out["skipped"] = len(encrypted)
            merged = dict(base)
            merged.update({k: out[k] for k in ("extracted", "skipped", "errors", "samples")})
            merged["message"] = base["message"] + " " + out["message"]
            return merged
        key_bytes = bytes.fromhex(key)
        for a in encrypted:
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
                target = dec_dir / safe_rel(MV_EXT.get(Path(a.path).suffix.lower(),
                                                      MZ_EXT.get(Path(a.path).suffix.lower(),
                                                                 Path(a.path).suffix)))
                # сохранить исходное имя файла и структуру папок
                stem = Path(a.path)
                tgt_name = dec_name(a.path)
                target = dec_dir / safe_rel(str(stem.parent / tgt_name))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(dec)
                out["extracted"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(str(target.relative_to(dec_dir)))
            except OSError as exc:
                out["errors"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(f"! {a.path}: {exc}")
        out["message"] = (f"MV/MZ: расшифровано {out['extracted']} файлов"
                          + (f", ошибок {out['errors']}" if out["errors"] else "") + ".")
        merged = dict(base)
        for k in ("extracted", "skipped", "errors"):
            merged[k] = base.get(k, 0) + out[k]
        merged["samples"] = (base.get("samples", []) + out["samples"])[:20]
        merged["message"] = base["message"] + " " + out["message"]
        return merged

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
