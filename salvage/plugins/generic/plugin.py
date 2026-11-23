"""Generic-плагин: универсальный аудит неизвестной папки/игры + общие контейнеры.

Дополнительно к индексу и zip-распаковке:
  * Unreal Engine .pak (v1–v11): индексирование, zlib-блоки, пометка AES/Oodle;
  * FMOD-банки .fsb/.bank (FSB4/FSB5): индексирование сэмплов и извлечение;
  * Wwise .pck (AKPK): индексирование (декодер банков — roadmap);
  * улики движка для незнакомых сборок.
"""
from __future__ import annotations

import struct
import zipfile
from pathlib import Path

from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin, note_limit
from ...core.util import (classify, head_bytes, human_bytes, human_int, iter_files,
                          rel_posix, safe_rel, sha256_file, sniff_magic)
from .._shared import copy_verbatim
from ...core import wwise
from . import fmod_fsb, unreal_pak

ENGINE_CLUES = {
    "unity": ("UnityPlayer.dll", "globalgamemanagers", "Managed/", "UnityEngine"),
    "unreal": ("Engine/", ".pak", ".utoc", "UnrealEngine"),
    "gamemaker": ("data.win",),
    "godot": ("project.godot", ".pck"),
    "renpy": (".rpa", "renpy"),
    "rpgmaker": ("RGSS", "System.json", ".rgss"),
}


class GenericPlugin(EnginePlugin):
    slug = "generic"
    display_name = "Generic (неизвестный движок)"
    can_extract = True
    notes = "Индекс, zip, Unreal .pak, FMOD .fsb/.bank, Wwise .pck, улики движка."

    def detect(self, root: Path) -> tuple[float, list[str]]:
        return 0.1, ["запасной режим"]

    # ------------------------------------------------------------------
    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        clues: dict[str, list[str]] = {}
        paks: list[Path] = []
        banks: list[Path] = []
        akpks: list[Path] = []
        bnk_wwise: list[Path] = []
        checked = 0
        capped = False
        for p in iter_files(root, exclude=ctx.exclude):
            if checked >= ctx.max_files:
                capped = True
                break
            checked += 1
            rel = rel_posix(p, root.resolve())
            low = rel.lower()
            for engine, needles in ENGINE_CLUES.items():
                if any(n.lower() in low for n in needles):
                    # .pck — не улика Godot, если это Wwise-банк (magic AKPK)
                    if engine == "godot" and low.endswith(".pck") \
                            and head_bytes(p, 4) == b"AKPK":
                        continue
                    clues.setdefault(engine, [])
                    if len(clues[engine]) < 5:
                        clues[engine].append(rel)
            ext = p.suffix.lower()
            if ext == ".pak":
                paks.append(p)
            elif ext in (".fsb", ".bank", ".fsb5"):
                kind = fmod_fsb.sniff(p)
                if kind in ("fsb5", "fsb4"):
                    banks.append(p)
            elif ext == ".pck" and head_bytes(p, 4) == b"AKPK":
                akpks.append(p)
            elif ext == ".bnk" and head_bytes(p, 4) == b"BKHD":
                bnk_wwise.append(p)

        if capped:
            note_limit(ds, "files", ctx.max_files, checked, "просмотр файлов")
        if clues:
            ds.meta["engine_clues"] = clues
            best = max(clues, key=lambda k: len(clues[k]))
            ds.add_finding(
                "info", "engine_clues",
                f"Возможный движок: {best} (улики: {', '.join(clues[best][:3])})",
                "Запустите: salvage scan <path> --engine " + best)

        if paks:
            self._scan_paks(ds, paks, ctx)
        if banks:
            self._scan_banks(ds, banks)
        if akpks or bnk_wwise:
            self._scan_wwise(ds, akpks, bnk_wwise)
        return ds

    # ------------------------------------------------------------------
    def _scan_wwise(self, ds: Dataset, pcks: list[Path], banks: list[Path]) -> None:
        """AKPK-пакеты и BKHD-банки: записи .wem с честной классификацией."""
        found: list[dict] = []
        totals = {"pck": 0, "bnk": 0, "wem": 0}
        for p in pcks[:200]:
            rel = rel_posix(p, ds.root)
            try:
                pck = wwise.read_pck(p)
            except (wwise.WwiseError, OSError, struct.error) as exc:
                ds.add_finding("warn", "wwise_pck_unreadable",
                               f"{rel}: .pck не прочитан — {exc}", path=rel)
                continue
            totals["pck"] += 1
            ds.meta.setdefault("wwise_pcks", []).append({
                "file": rel, "version": pck.version, "entries": len(pck.entries),
                "languages": pck.languages,
            })
            ds.add_finding("info", "wwise_pck",
                           f"{rel}: Wwise .pck v{pck.version}, медиа {len(pck.entries)}",
                           "Экспорт .wem выполняется при extract; Vorbis-версии Wwise "
                           "не являются стандартным Ogg — статус пишется в отчёт.", path=rel)
            for e in pck.entries:
                found.append(self._wwise_asset(ds, rel, p, e, totals))
        for p in banks[:200]:
            rel = rel_posix(p, ds.root)
            try:
                bnk = wwise.read_bnk(p)
            except (wwise.WwiseError, OSError, struct.error) as exc:
                ds.add_finding("warn", "wwise_bnk_unreadable",
                               f"{rel}: .bnk не прочитан — {exc}", path=rel)
                continue
            totals["bnk"] += 1
            bank_meta = {
                "file": rel, "version": bnk.version, "bank_id": bnk.bank_id,
                "entries": len(bnk.entries), "chunks": [c[0] for c in bnk.chunks],
                "hirc_total": bnk.hirc_total,
                "hirc_types": {wwise.HIRC_TYPE_NAMES.get(k, f"type-{k}"): v
                               for k, v in sorted(bnk.hirc_types.items())},
            }
            if bnk.hirc_error:
                bank_meta["hirc_error"] = bnk.hirc_error
            ds.meta.setdefault("wwise_banks", []).append(bank_meta)
            hirc_note = (f"HIRC: объектов {bnk.hirc_total}" if bnk.hirc_total else
                         "HIRC отсутствует или не разобран")
            if bnk.hirc_error:
                ds.add_finding("warn", "wwise_hirc_error",
                               f"{rel}: HIRC не разобран — {bnk.hirc_error}", path=rel)
            ds.add_finding("info", "wwise_bnk",
                           f"{rel}: Wwise .bnk v{bnk.version}, медиа {len(bnk.entries)}",
                           f"DIDX/DATA разобраны; {hirc_note}. Граф событий — отдельная задача.",
                           path=rel)
            for e in bnk.entries:
                found.append(self._wwise_asset(ds, rel, p, e, totals))
        if totals["wem"]:
            ds.meta["wwise_wems"] = {"count": totals["wem"],
                                     "pcks": totals["pck"], "banks": totals["bnk"]}
        if found:
            statuses: dict[str, int] = {}
            for item in found:
                statuses[item["status"]] = statuses.get(item["status"], 0) + 1
            ds.meta["wwise_wem_status"] = statuses
            if statuses.get("unknown"):
                ds.add_finding(
                    "warn", "wwise_wem_unknown",
                    f"Wwise: медиа неизвестного кодека — {statuses['unknown']}",
                    "Они будут экспортированы как .wem со статусом unknown (без маскировки под .ogg).")

    def _wwise_asset(self, ds: Dataset, rel: str, path: Path,
                     entry: "wwise.WemEntry", totals: dict) -> dict:
        try:
            payload = wwise.read_wem_bytes(path, entry)
        except OSError:
            payload = b""
        status = wwise.wem_status(payload) if payload else "missing"
        ext = wwise.wem_extension(payload) if payload else "wem"
        totals["wem"] += 1
        a = ds.add_asset(f"{rel}::wem_{entry.wem_id}.{ext}", kind="audio",
                         size=entry.size, container=rel,
                         wwise_id=entry.wem_id, wwise_offset=entry.offset,
                         wwise_source=entry.source, wwise_status=status)
        a.extra["wwise_language"] = entry.language
        return {"status": status, "id": entry.wem_id}

    # ------------------------------------------------------------------
    def _scan_paks(self, ds: Dataset, paks: list[Path], ctx: EngineContext) -> None:
        if len(paks) > 200:
            note_limit(ds, "paks", 200, len(paks), "разбор UE .pak")
        info = []
        for p in paks[:200]:
            rel = rel_posix(p, ds.root)
            if not unreal_pak.sniff(p):
                continue
            try:
                pak = unreal_pak.read_pak(p)
            except (unreal_pak.PakError, OSError, ValueError) as exc:
                ds.add_finding("warn", "ue_pak_unreadable",
                               f"{rel}: .pak не прочитан — {exc}", path=rel)
                continue
            enc = sum(1 for e in pak.entries if e.encrypted)
            methods = sorted({e.compression for e in pak.entries})
            ds.meta.setdefault("ue_paks", []).append({
                "file": rel, "version": pak.version, "mount": pak.mount_point,
                "entries": len(pak.entries), "encrypted_entries": enc,
                "compression": methods,
                "compression_names": [n for n in pak.compression_names if n],
            })
            ds.add_finding("info", "ue_pak",
                           f"{rel}: UE .pak v{pak.version}, файлов {human_int(len(pak.entries))}",
                           f"Точка монтирования: {pak.mount_point}; сжатие: {', '.join(methods) or 'нет'}"
                           + (f"; зашифровано записей: {enc}" if enc else ""), path=rel)
            for e in pak.entries[:50000]:
                a = ds.add_asset(e.name, kind=classify(e.name), size=e.uncompressed,
                                 container=rel, pak_offset=e.offset,
                                 pak_size=e.size, pak_method=e.method)
                if e.encrypted:
                    a.extra["encrypted"] = "AES"
            info.append((rel, pak, len(pak.entries)))
        ds.meta["ue_pak_objects"] = {rel: pak for rel, pak, _ in info}
        if any(pak.encrypted_index for _, pak, _ in info):
            ds.add_finding("warn", "ue_pak_encrypted_index",
                           "Индекс .pak зашифрован (AES)", "Нужен ключ AES-256 из бинарника игры.")

    # ------------------------------------------------------------------
    def _scan_banks(self, ds: Dataset, banks: list[Path]) -> None:
        if len(banks) > 300:
            note_limit(ds, "banks", 300, len(banks), "разбор FMOD-банков")
        for p in banks[:300]:
            rel = rel_posix(p, ds.root)
            try:
                b = fmod_fsb.read_fsb(p)
            except (fmod_fsb.FsbError, OSError, ValueError) as exc:
                ds.add_finding("warn", "fmod_unreadable", f"{rel}: {exc}", path=rel)
                continue
            codecs: dict[str, int] = {}
            for s in b.samples:
                codecs[s.codec_name] = codecs.get(s.codec_name, 0) + 1
            ds.meta.setdefault("fmod_banks", []).append({
                "file": rel, "version": b.version, "samples": len(b.samples),
                "codecs": codecs,
            })
            ds.add_finding("info", "fmod_bank",
                           f"{rel}: {b.version}, сэмплов {len(b.samples)}",
                           "Кодеки: " + ", ".join(f"{k}×{v}" for k, v in sorted(codecs.items())))
            for s in b.samples:
                a = ds.add_asset(f"{rel}::{s.name}.{s.extension}", kind="audio",
                                 size=s.data_size, container=rel,
                                 fsb_index=s.index, fsb_offset=s.data_offset,
                                 fsb_size=s.data_size, fsb_codec=s.codec_name)
                a.extra["fsb_channels"] = s.channels
                a.extra["fsb_frequency"] = s.frequency

    # ------------------------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        summary = copy_verbatim(dataset, dest, ctx, only_kinds)
        summary["extracted"] = summary.get("extracted", 0)
        extra_msgs: list[str] = []

        # --- Unreal pak ---
        if only_kinds is None or "archive" in only_kinds or "data" in only_kinds:
            pak_stats = self._extract_paks(dataset, Path(dest), ctx, only_kinds)
            summary["extracted"] += pak_stats["extracted"]
            summary["skipped"] += pak_stats["skipped"]
            summary["errors"] += pak_stats["errors"]
            summary["samples"] = (summary["samples"] + pak_stats["samples"])[:20]
            if pak_stats["message"]:
                extra_msgs.append(pak_stats["message"])

        # --- FMOD ---
        if only_kinds is None or "audio" in only_kinds:
            bank_stats = self._extract_banks(dataset, Path(dest), ctx)
            summary["extracted"] += bank_stats["extracted"]
            summary["errors"] += bank_stats["errors"]
            summary["samples"] = (summary["samples"] + bank_stats["samples"])[:20]
            if bank_stats["message"]:
                extra_msgs.append(bank_stats["message"])

        # --- Wwise ---
        if only_kinds is None or "audio" in only_kinds:
            wwise_stats = self._extract_wwise(dataset, Path(dest), ctx)
            summary["extracted"] += wwise_stats["extracted"]
            summary["skipped"] += wwise_stats["skipped"]
            summary["errors"] += wwise_stats["errors"]
            summary["samples"] = (summary["samples"] + wwise_stats["samples"])[:20]
            if wwise_stats["message"]:
                extra_msgs.append(wwise_stats["message"])

        # --- zip ---
        zip_stats = self._extract_zips(dataset, Path(dest), ctx)
        summary["extracted"] += zip_stats["extracted"]
        summary["errors"] += zip_stats["errors"]
        if zip_stats["message"]:
            extra_msgs.append(zip_stats["message"])

        if extra_msgs:
            summary["message"] = (summary.get("message", "") + " " + " ".join(extra_msgs)).strip()
        return summary

    # ------------------------------------------------------------------
    def _extract_paks(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                      only_kinds: set[str] | None) -> dict:
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        statuses: dict[str, int] = {}
        paks: dict[str, object] = dataset.meta.get("ue_pak_objects") or {}
        for rel, pak in paks.items():
            for e in pak.entries:
                if only_kinds and classify(e.name) not in only_kinds:
                    out["skipped"] += 1
                    statuses["filtered"] = statuses.get("filtered", 0) + 1
                    continue
                data, status = unreal_pak.read_entry_data(pak, e, ctx.max_asset_bytes)
                if data is None:
                    # статус просрочен в отчёт: «пропущено» не должно скрывать причину
                    out["skipped"] += 1
                    statuses[status] = statuses.get(status, 0) + 1
                    if status != "encrypted":
                        out["errors"] += 1
                    continue
                statuses[status] = statuses.get(status, 0) + 1
                target = dest / "pak" / Path(rel).stem / safe_rel(e.name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                out["extracted"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(f"{rel}:{e.name}")
        if out["extracted"] or out["skipped"]:
            detail = ", ".join(f"{k}×{v}" for k, v in sorted(statuses.items()))
            out["message"] = (f"UE .pak: извлечено {out['extracted']}, "
                              f"пропущено {out['skipped']} ({detail}).")
            dataset.meta["ue_pak_statuses"] = statuses
        return out

    def _extract_banks(self, dataset: Dataset, dest: Path, ctx: EngineContext) -> dict:
        out = {"extracted": 0, "errors": 0, "samples": [], "message": ""}
        for a in dataset.assets:
            if "fsb_index" not in a.extra or not a.container:
                continue
            src = dataset.root / a.container
            try:
                fsb = fmod_fsb.read_fsb(src)
                idx = a.extra["fsb_index"]
                if idx >= len(fsb.samples):
                    out["errors"] += 1
                    continue
                sample = fsb.samples[idx]
                payload = fmod_fsb.sample_payload(fsb, sample)
                target = dest / "fmod" / Path(a.container).stem / safe_rel(a.path.split("::")[-1])
                target.parent.mkdir(parents=True, exist_ok=True)
                if sample.codec_name == "vorbis":
                    ogg = fmod_fsb.build_ogg(sample, payload)
                    if ogg:
                        target = target.with_suffix(".ogg.raw")
                        payload = ogg
                target.write_bytes(payload[: ctx.max_asset_bytes])
                out["extracted"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(str(target.relative_to(dest)))
            except (OSError, fmod_fsb.FsbError) as exc:
                out["errors"] += 1
                if len(out["samples"]) < 10:
                    out["samples"].append(f"! {a.path}: {exc}")
        if out["extracted"]:
            out["message"] = f"FMOD: извлечено сэмплов {out['extracted']}."
        return out

    def _extract_wwise(self, dataset: Dataset, dest: Path, ctx: EngineContext) -> dict:
        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [], "message": ""}
        statuses: dict[str, int] = {}
        for a in dataset.assets:
            if "wwise_id" not in a.extra or not a.container:
                continue
            src = dataset.root / a.container
            entry = wwise.WemEntry(wem_id=a.extra["wwise_id"],
                                   offset=a.extra["wwise_offset"],
                                   size=a.size, container=a.container)
            try:
                payload = wwise.read_wem_bytes(src, entry)
            except OSError as exc:
                out["errors"] += 1
                continue
            status = wwise.wem_status(payload)
            statuses[status] = statuses.get(status, 0) + 1
            ext = wwise.wem_extension(payload)
            target = dest / "wwise" / Path(a.container).stem / f"wem_{entry.wem_id}.{ext}"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload[: ctx.max_asset_bytes])
            out["extracted"] += 1
            if len(out["samples"]) < 10:
                out["samples"].append(f"{target.relative_to(dest)} ({status})")
        if out["extracted"]:
            detail = ", ".join(f"{k}×{v}" for k, v in sorted(statuses.items()))
            out["message"] = f"Wwise: .wem {out['extracted']} ({detail})."
            dataset.meta["wwise_wem_status"] = statuses
        return out

    def _extract_zips(self, dataset: Dataset, dest: Path, ctx: EngineContext) -> dict:
        out = {"extracted": 0, "errors": 0, "samples": [], "message": ""}
        for a in dataset.assets:
            if a.kind != "archive" or a.container:
                continue
            p = dataset.root / a.path
            if not p.is_file() or not zipfile.is_zipfile(p):
                continue
            target = dest / "unzipped" / safe_rel(a.path).replace("/", "_")
            try:
                with zipfile.ZipFile(p) as zf:
                    for info in zf.infolist():
                        if info.is_dir():
                            continue
                        name = safe_rel(info.filename)
                        if not name:
                            continue
                        dest_file = target / name
                        dest_file.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(info) as src, open(dest_file, "wb") as dst:
                            dst.write(src.read(ctx.max_asset_bytes))
                        out["extracted"] += 1
                        if len(out["samples"]) < 10:
                            out["samples"].append(f"{a.path}:{info.filename}")
            except (zipfile.BadZipFile, OSError):
                out["errors"] += 1
        if out["extracted"]:
            out["message"] = f"Распаковано из zip: {out['extracted']} файлов."
        return out
