# salvage

**Аудит и восстановление ассетов игр. Не только Unity.**

`salvage` — открытый инструмент в духе [AssetRipper](https://github.com/AssetRipper/AssetRipper), но построенный как
**мультидвижковое ядро с плагинами**: Unity, Godot, GameMaker Studio, RPG Maker (MV/MZ/XP/VX/Ace), Ren'Py
и универсальный режим для всего остального.

Две задачи, которые решает инструмент:

1. **Аудит** — что лежит в сборке, что сломано, что зашифровано, где дубликаты и утечки конфигов.
2. **Восстановление** — извлечение ассетов в обычные форматы и распаковка контейнеров.

---

## Установка

```bash
cd salvage
pip install -e .                 # ядро и все движки, кроме глубокого Unity
pip install -e ".[unity]"        # + UnityPy для глубокого разбора Unity-бандлов
```

Python ≥ 3.10, без обязательных нативных зависимостей.

## Быстрый старт

```bash
salvage engines                                # список плагинов
salvage detect /path/to/game                   # кто это?
salvage scan /path/to/game --deep              # аудит → salvage-report/report.html
salvage extract /path/to/game --out ./unpacked # извлечение ассетов
salvage audit /path/to/game                    # скан + отчёты одной командой
```

Веб-пульт (локально, без отправки данных наружу):

```bash
python -m salvage.web --port 8741
```

Демо-отчёты по синтетическому стенду всех движков: `demo/index.html` (собирается `python build_demo.py`).

## Что умеет по движкам

| Движок | Детект | Аудит | Извлечение | Статус |
|---|---|---|---|---|
| **Unity** | `globalgamemanagers`, `*_Data/`, магия `UnityFS` | индекс, deep-разбор через UnityPy, внешние ссылки | побайтово + Texture2D/TextAsset/AudioClip/Mesh через UnityPy | работает; без UnityPy — только индекс |
| **Godot** | `GDPC`, `project.godot`, `.tscn/.tres` | PCK v1/v2 (+встроенный в exe), зависимости `res://`, битые ссылки | распаковка PCK по смещениям | работает; зашифрованные PCK честно помечаются |
| **GameMaker** | `FORM/DATA`, `data.win`, `.yy/.yyp` | карта чанков, целостность, ресурсы проекта | побайтово | работает; байткод GML не декомпилируется (roadmap) |
| **RPG Maker MV/MZ** | магия `RPGMV/RPGMZ`, `.rpgmvp/.png_`, `System.json` | ключ, карты, события, шифрование | **расшифровка** PNG/OGG/M4A | работает полностью |
| **RPG Maker XP/VX/Ace** | `RGSSAD` | версия архива | пока копирование архива целиком | roadmap |
| **Ren'Py** | `RPA-3.x`, `.rpyc` | карта архива, индекс скриптов | извлечение из RPA | работает; `.rpyc` не декомпилируется (UnRen — внешний шаг) |
| **generic** | — | полный индекс, энтропия, улики движка, zip-распаковка | копирование + zip | работает |

Общие анализаторы (для любого движка):

- дубликаты по `sha256` и «сколько занимают лишние копии»;
- **битые ссылки**: зависимости контейнеров/сцен → отсутствующие файлы;
- высокая энтропия (возможное шифрование/упаковка);
- инвентарь потенциально чувствительных строк (`apiKey`, токены, приватные ключи, firebase, IP);
- топ самых тяжёлых файлов.

## Форматы отчётов

- `report.html` — автономный (без внешних ресурсов), стиль «терминальный пульт»;
- `scan.json` — машиночитаемый полный дамп (`totals`, `assets`, `findings`, `meta`);
- `report.md` — для PR/issue.

## Коды возврата CLI (для CI)

| Код | Значение |
|---|---|
| 0 | чисто или только `info` |
| 1 | есть предупреждения |
| 2 | есть ошибки |
| 3 | сбой выполнения |

Пример для CI: `salvage scan build/ —deep --formats json || exit $?`.

## Архитектура

```
salvage/
├── core/
│   ├── model.py        # Asset, Finding, Dataset — единая модель
│   ├── plugin_base.py  # контракт EnginePlugin (detect/scan/extract)
│   ├── registry.py     # реестр движков, автодетект
│   ├── scan.py         # оркестратор скана
│   ├── analyze.py      # дубликаты, ссылки, энтропия, секреты
│   └── util.py         # классификация, магия, sha256, safe_rel
├── plugins/
│   ├── unity/  godot/  gamemaker/  rpgmaker/  renpy/  generic/
├── report/             # html / json / md
├── web.py              # локальный пульт (http.server, без зависимостей)
└── cli.py              # argparse-интерфейс
```

Плагин обязан реализовать `slug`, `display_name`, `detect(root) -> (score, evidence)` и `scan(root, ctx)`;
`extract(...)` — опционально. Ядро не знает ни одного имени движка: всё через реестр.

### Новый движок за 60 строк

```python
# salvage/plugins/mygame/plugin.py
from ...core.model import Dataset
from ...core.plugin_base import EngineContext, EnginePlugin

class MyGamePlugin(EnginePlugin):
    slug, display_name, can_extract = "mygame", "MyGame Engine", True

    def detect(self, root):
        return (0.9, ["найден .mygame-архив"]) if (root / "data.mygame").exists() else (0.0, [])

    def scan(self, root, ctx: EngineContext) -> Dataset:
        ds = Dataset(self.slug, self.display_name, root)
        ds.add_asset("data.mygame", "archive", (root / "data.mygame").stat().st_size)
        for ref in ...:
            ds.add_dep("data.mygame", ref)   # ядро само найдёт битые ссылки
        return ds
```

Зарегистрируйте класс в `core/registry.py::build_registry()`. Отчёты, дубликаты, секреты и CLI
подхватят его автоматически.

## Происхождение идей и лицензия

- Вдохновение архитектурой **[AssetRipper](https://github.com/AssetRipper/AssetRipper)** (C#, **GPL-3.0**):
  слоистость «модель ассетов → экспорт-модули → сборка проекта», идея primary content extraction.
  **Код AssetRipper не копировался и не включается** — GPL-3.0 это копилефт, а `salvage` распространяется
  под MIT и задуман как библиотека/CLI для любого проекта.
- Глубокий Unity-разбор — через **[UnityPy](https://github.com/K0lb3/UnityPy)** (MIT, зависимость по желанию).
- GameMaker-формат описан сообществом (Underanalyzer/UndertaleModTool); код парсера — оригинальный.

`salvage` — MIT. Используйте только на своих или явно разрешённых сборках; извлечение чужих
ассетов регулируется авторским правом.

## Roadmap

См. **[ROADMAP.md](ROADMAP.md)** — приоритеты, известные ограничения и идеи (декомпиляция GML,
`.rpyc`, RGSS, Unreal `.pak/.utoc`, Cocos/Laya, инкрементальные сканы, SARIF-вывод для CI).
