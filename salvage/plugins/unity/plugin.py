"""Unity-плагин: индекс сборки + разбор через UnityPy (опционально).

Идеи архитектуры взяты из AssetRipper (слои Assets → Export.Modules → Export),
но код написан с нуля. UnityPy — сторонняя MIT-библиотека, поэтому тяжёлый
разбор подключается только при `pip install salvage[unity]` и в deep-режиме.
"""
from __future__ import annotations

import re
from pathlib import Path

from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin
from ...core.util import classify, head_bytes, human_int, iter_files, rel_posix, sha256_file, sniff_magic
from .._shared import copy_verbatim, merge_summaries

UNITY_MAGICS = {"UnityFS", "UnityWeb", "UnityRaw", "UnityArchive"}
UNITY_CONTAINER_EXT = {".assets", ".resource", ".resS", ".bundle", ".unity3d",
                       ".ab", ".unity", ".bytes"}

# стеклянная типология для отчёта
OBJ_KIND = {
    "Texture2D": "texture", "Sprite": "texture", "RenderTexture": "texture",
    "AudioClip": "audio", "VideoClip": "video",
    "Mesh": "mesh", "SkinnedMeshRenderer": "mesh", "MeshRenderer": "mesh",
    "Material": "shader", "Shader": "shader",
    "Font": "font", "TextAsset": "data", "ScriptableObject": "data",
    "MonoBehaviour": "data", "GameObject": "scene", "Transform": "scene",
    "AnimatorController": "anim", "AnimationClip": "anim",
    "SceneManager": "scene",
}


class UnityPlugin(EnginePlugin):
    slug = "unity"
    display_name = "Unity"
    can_extract = True
    notes = "Индекс .assets/.bundle; глубокий разбор и экспорт — через UnityPy."

    # ------------------------------------------------------------------
    def detect(self, root: Path) -> tuple[float, list[str]]:
        score = 0.0
        evidence: list[str] = []
        data_dirs = 0
        magic_hits = 0
        ext_hits = 0
        names = {"globalgamemanagers", "globalgamemanagers.assets", "level0",
                 "resources.assets", "sharedassets0.assets"}
        checked = 0
        for p in iter_files(root):
            low = p.name.lower()
            if "unitypy" in str(p).lower():  # не путать со собой
                pass
            if low in names:
                score += 0.25
                evidence.append(f"файл сборки: {p.name}")
            if p.parent.name.endswith("_Data"):
                data_dirs += 1
            ext = p.suffix.lower()
            if ext in (".assets", ".bundle", ".unity3d") and not low.endswith(".dll"):
                ext_hits += 1
            if not low.endswith((".assets", ".bundle", ".unity3d", ".resource")):
                checked += 1
                if checked <= 40000 and ext_hits == 0 and magic_hits == 0 and p.stat().st_size > 1024:
                    head = head_bytes(p, 24)
                    if any(head.startswith(m.encode()) for m in UNITY_MAGICS):
                        magic_hits += 1
                        if len(evidence) < 6:
                            evidence.append(f"магия {head[:8]!r}: {p.name}")
            if ext == ".dll" and p.parent.name in ("Managed", "ManagedStripped"):
                score += 0.1
            if score >= 0.9:
                break
        if data_dirs:
            score += 0.35
            evidence.append(f"{data_dirs} файлов в *_Data/")
        if ext_hits:
            score += min(0.4, 0.1 * ext_hits)
            evidence.append(f"{ext_hits} файлов .assets/.bundle/.unity3d")
        if magic_hits:
            score += min(0.5, 0.15 * magic_hits)
            evidence.append(f"{magic_hits} контейнеров с магией Unity")
        return min(score, 0.98), evidence[:10]

    # ------------------------------------------------------------------
    def scan(self, root: Path, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        root_r = root.resolve()
        candidates: list[Path] = []
        for p in iter_files(root, exclude=ctx.exclude):
            rel = rel_posix(p, root_r)
            try:
                size = p.stat().st_size
            except OSError:
                continue
            head = head_bytes(p, 24)
            magic = sniff_magic(head, rel)
            kind = classify(rel, magic)
            sha = sha256_file(p) if (ctx.hash_files and size <= ctx.hash_limit_mb << 20) else None
            a = ds.add_asset(rel, kind=kind, size=size, sha256=sha)
            if magic:
                a.extra["magic"] = magic
            if (magic in ("unityfs", "unityweb", "unityraw", "unityarchive")
                    or p.suffix.lower() in UNITY_CONTAINER_EXT):
                candidates.append(p)
                a.extra["unity_container"] = True

        if not candidates:
            ds.add_finding("warn", "unity_no_containers",
                           "Не найдено ни одного Unity-контейнера",
                           "Файлы .assets/.bundle/UnityFS отсутствуют — возможно, "
                           "сборка не Unity или ассеты упакованы кастомным способом.")
            return ds

        ds.meta["containers"] = [rel_posix(p, root_r) for p in candidates[:500]]
        if not ctx.deep:
            ds.add_finding("info", "unity_index_only",
                           f"Индекс: {len(candidates)} Unity-контейнеров",
                           "Глубокий разбор (типы объектов, внешние ссылки) — запустите с --deep.")
            return ds

        try:
            import UnityPy  # noqa: F401
        except ImportError:
            ds.add_finding("warn", "unitypy_missing",
                           "UnityPy не установлен — глубокий разбор недоступен",
                           "Установите: pip install salvage[unity]")
            return ds

        self._deep_scan(ds, candidates, root_r, ctx)
        return ds

    # ------------------------------------------------------------------
    def _deep_scan(self, ds: Dataset, candidates: list[Path], root_r: Path,
                   ctx: EngineContext) -> None:
        import logging
        import warnings

        import UnityPy

        # UnityPy печатает собственные ошибки парсинга в лог — глушим,
        # а провалы считаем сами и показываем честно.
        logging.getLogger("UnityPy").setLevel(logging.CRITICAL)
        for name in list(logging.root.manager.loggerDict):
            if name.startswith("UnityPy"):
                logging.getLogger(name).setLevel(logging.CRITICAL)
        warnings.filterwarnings("ignore", category=Warning, module="UnityPy.*")
        try:
            if not UnityPy.config.FALLBACK_UNITY_VERSION:
                UnityPy.config.FALLBACK_UNITY_VERSION = "2022.3.0f1"
        except Exception:
            pass
        type_counts: dict[str, int] = {}
        parsed = 0
        failed = 0
        externals: set[str] = set()
        object_assets = 0
        if len(candidates) > ctx.max_containers:
            from ...core.plugin_base import note_limit
            note_limit(ds, "containers", ctx.max_containers, len(candidates),
                       "глубокий разбор Unity-контейнеров")
        for p in candidates[: ctx.max_containers]:
            try:
                env = UnityPy.load(str(p))
            except Exception:
                failed += 1
                continue
            parsed += 1
            rel = rel_posix(p, root_r)
            local = 0
            for obj in env.objects:
                tname = getattr(getattr(obj, "type", None), "name", str(getattr(obj, "type", "?")))
                type_counts[tname] = type_counts.get(tname, 0) + 1
                local += 1
                object_assets += 1
                kind = OBJ_KIND.get(tname, "data")
                try:
                    name = getattr(obj, "peek_name", None)
                    name = obj.peek_name() if callable(name) else None
                except Exception:
                    name = None
                if name:
                    ds.add_asset(f"<{rel}>{tname}/{name}", kind=kind, container=rel,
                                 object_type=tname)
                else:
                    ds.add_asset(f"<{rel}>{tname}#{obj.path_id}", kind=kind, container=rel,
                                 object_type=tname)
            for af in getattr(env, "files", {}).values():
                for ext_ref in getattr(af, "externals", []) or []:
                    try:
                        path = ext_ref.path
                        type_name = ext_ref.type.name
                    except AttributeError:
                        continue
                    if path:
                        externals.add(f"{path}:{type_name}")
                        ds.add_dep(rel, path if str(path).startswith("archive:/") else Path(str(path)).name)

        ds.meta["unity"] = {
            "containers_parsed": parsed,
            "containers_failed": failed,
            "object_total": object_assets,
            "types": dict(sorted(type_counts.items(), key=lambda kv: -kv[1])[:40]),
            "external_refs": len(externals),
        }
        ds.add_finding("info", "unity_deep",
                       f"Разобрано {parsed} контейнеров, {human_int(object_assets)} объектов",
                       f"Типы: " + ", ".join(f"{k}×{v}" for k, v in
                                             sorted(type_counts.items(), key=lambda kv: -kv[1])[:10]))
        if failed:
            ds.add_finding("warn", "unity_parse_failed",
                           f"{failed} контейнеров не удалось разобрать",
                           "Возможны нестандартные версии/сжатие; файлы всё равно будут извлечены побайтово.",
                           count=failed)
        # ссылки на внешние бандлы, которых нет рядом
        names = {a.path.rsplit("/", 1)[-1] for a in ds.assets}
        missing = [e for e in externals if e.split(":")[0].rsplit("/", 1)[-1] not in names]
        if missing:
            ds.add_finding("warn", "unity_missing_externals",
                           f"Внешние ссылки на отсутствующие файлы: {len(missing)}",
                           "; ".join(sorted(missing)[:6]), count=len(missing))

    # ------------------------------------------------------------------
    def extract(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                only_kinds: set[str] | None = None) -> dict:
        base = copy_verbatim(dataset, dest, ctx, only_kinds)
        # если deep-разбор делался, объекты контейнеров можно выгружать через UnityPy
        try:
            import UnityPy
        except ImportError:
            base["message"] += " UnityPy не установлен: объекты контейнеров не извлекались."
            return base
        if not dataset.meta.get("unity"):
            return base
        return merge_summaries(base, self._extract_objects(dataset, dest, ctx, only_kinds))

    def _extract_objects(self, dataset: Dataset, dest: Path, ctx: EngineContext,
                         only_kinds: set[str] | None) -> dict:
        import UnityPy
        from ...core.util import safe_rel

        out = {"extracted": 0, "skipped": 0, "errors": 0, "samples": [],
               "message": ""}
        containers = dataset.meta.get("containers") or []
        mapping = {"Texture2D": "Textures", "Sprite": "Sprites", "TextAsset": "TextAssets",
                   "AudioClip": "Audio", "Mesh": "Meshes", "Font": "Fonts"}
        for rel in containers:
            p = dataset.root / rel
            if not p.is_file():
                continue
            try:
                env = UnityPy.load(str(p))
            except Exception:
                out["errors"] += 1
                continue
            for obj in env.objects:
                tname = getattr(getattr(obj, "type", None), "name", "")
                sub = mapping.get(tname)
                if not sub:
                    continue
                kind = OBJ_KIND.get(tname, "data")
                if only_kinds and kind not in only_kinds:
                    out["skipped"] += 1
                    continue
                try:
                    data = obj.read()
                    name = getattr(data, "m_Name", None) or f"{tname}_{obj.path_id}"
                    name = safe_rel(str(name)) or f"{tname}_{obj.path_id}"
                    target_dir = Path(dest) / sub / safe_rel(rel).replace("/", "_")
                    target_dir.mkdir(parents=True, exist_ok=True)
                    if tname in ("Texture2D", "Sprite"):
                        img = data.image
                        img.save(target_dir / f"{name}.png")
                    elif tname == "TextAsset":
                        raw = getattr(data, "m_Script", None)
                        if raw is None:
                            raw = getattr(data, "script", b"")
                        if isinstance(raw, str):
                            raw = raw.encode("utf-8")
                        (target_dir / f"{name}.txt").write_bytes(raw)
                    elif tname == "AudioClip":
                        ext = getattr(data, "extension", "wav") or "wav"
                        (target_dir / f"{name}.{ext}").write_bytes(data.samples)
                    elif tname == "Mesh":
                        data.export(str(target_dir / name))
                    elif tname == "Font":
                        (target_dir / f"{name}.fontdata").write_bytes(
                            bytes(getattr(data, "m_FontData", b"") or b""))
                    out["extracted"] += 1
                    if len(out["samples"]) < 10:
                        out["samples"].append(f"{sub}/{name}")
                except Exception as exc:
                    out["errors"] += 1
                    if len(out["samples"]) < 10:
                        out["samples"].append(f"! {tname}: {exc}")
        out["message"] = (f"UnityPy: извлечено объектов {out['extracted']}, "
                          f"ошибок {out['errors']}.")
        return out
