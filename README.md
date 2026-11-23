# salvage

**Аудит и восстановление ассетов игр. Не только Unity.**

`salvage` — самостоятельный инструмент на **мультидвижковом ядре с плагинами**: Unity, Godot,
GameMaker Studio, RPG Maker (MV/MZ/XP/VX/Ace), Ren'Py и универсальный слой
(Unreal `.pak`, FMOD FSB, Wwise, zip, неизвестные сборки).
Вся реализация — собственная: свои форматы-парсеры, свои модели данных, свой отчёт.

Две задачи, которые решает инструмент:

1. **Аудит** — что лежит в сборке, что сломано, что зашифровано, где дубликаты и утечки конфигов.
2. **Восстановление** — извлечение ассетов в обычные форматы, распаковка контейнеров, декомпиляция, конвертация данных.

---

## Установка

```bash
cd salvage
pip install -e .                 # ядро и все движки, кроме глубокого Unity
pip install -e ".[unity]"        # + UnityPy для глубокого разбора Unity-бандлов
pip install pillow               # опционально: нарезка кадров спрайтов GameMaker
```

Python ≥ 3.10, без обязательных нативных зависимостей.

## Быстрый старт

```bash
salvage engines                                # список плагинов
salvage detect /path/to/game                   # кто это?
salvage audit /path/to/game                    # скан + doctor + отчёты
salvage scan /path/to/game --deep --doctor     # только аудит
salvage extract /path/to/game --out ./unpacked # извлечение ассетов
```

Ключевые опции извлечения:

```bash
salvage extract game/ --texture-format qoi     # текстуры GameMaker: png | qoi | bz2 | both
salvage extract game/ --rm-key @www/data/System.json   # ключ MV/MZ из System.json
salvage extract game/ --no-data-json           # не конвертировать rxdata/rvdata2
salvage extract game/ --rpyc-strings           # .rpyc: только строки, без склейки .rpy
```

Веб-пульт (локально, без отправки данных наружу):

```bash
python -m salvage.web --port 8741
```

Демо-отчёты по синтетическому стенду всех движков: `demo/index.html` (собирается `python build_demo.py`).


## Тесты

Фикстуры в git не лежат — они собираются детерминированно из кода:

```bash
python tests/make_fixtures.py            # стенды всех движков
python tests/make_fixtures.py regress    # минимальные регресс-фикстуры (по одной на баг)
python tests/make_asset_tone.py          # real ogg для сквозного теста FMOD→Ogg
python -W ignore -m unittest discover -s tests
```

114 тестов. Опциональные зависимости учитываются аккуратно: без `lz4` тест
проверяет статус `unsupported:lz4-python-missing`, без `soundfile` PCM-сверка
пропускается (`skipUnless`), а не выдаётся за пройденную.

## Что умеет по движкам

| Движок | Детект | Аудит | Извлечение | Статус |
|---|---|---|---|---|
| **Unity** | `globalgamemanagers`, `*_Data/`, магия `UnityFS` | индекс, deep-разбор через UnityPy, внешние ссылки | побайтово + Texture2D/TextAsset/AudioClip/Mesh | работает; без UnityPy — только индекс |
| **Godot** | `GDPC`, `project.godot`, `.tscn/.tres` | PCK v1/v2 (+встроенный в exe), зависимости `res://`, битые ссылки | распаковка PCK по смещениям | работает; зашифрованные PCK помечаются |
| **GameMaker** | `FORM/DATA`, `data.win`, `.yy/.yyp` | карта чанков, SPRT/TPAG/TXTR, SOND/AUDO, STRG, целостность | **спрайты (кадры+rect), текстуры PNG/QOI/BZ2, аудио из `AUDO` и `audiogroup*.dat`, `manifest.json`, `strings.txt`** | работает; GML-байткод не декомпилируется (roadmap) |
| **RPG Maker MV/MZ** | магия `RPGMV/RPGMZ`, `.rpgmvp/.png_`, `System.json` | ключ, карты, события, шифрование | **расшифровка** PNG/OGG/M4A | работает полностью |
| **RPG Maker XP/VX/Ace** | `RGSSAD` v1/v2/v3 | индекс архива, данные `.rxdata/.rvdata2` | **расшифровка RGSSAD v1/v3** + **конвертация данных в JSON** | работает; `.rgss2a` = версия 1 (формата v2 нет), байт 2 помечается как патч |
| **Ren'Py** | `RPA-3.x`, `.rpyc` | карта архива, структура скриптов | **распаковка RPA**, **декомпиляция `.rpyc`** (RPC2 и старый формат) в приближённый `.rpy` | работает; полная побайтовая реконструкция — roadmap |
| **Unreal (generic)** | `.pak`, улики `Engine/` | **индекс `.pak` v1–v11**, точка монтирования, сжатие, AES-пометки | **распаковка zlib и LZ4 (свой raw-block декодер)**, v10+ FDI | работает; Oodle и шифрованные — помечаются (`compression:oodle`, `encrypted`) |
| **FMOD (generic)** | `FSB5`, `FSB4` | индексирование сэмплов, кодеки, частоты | извлечение сэмплов; **Vorbis собирается в настоящий `.ogg`** (страницы + CRC32) | работает; если setup недостижим — честный `headers-unrecoverable` |
| **Wwise (generic)** | `AKPK`, `BKHD` | `.pck` (v1/v2: языки/банки/стримы), `.bnk` по чанкам, HIRC-инвентарь | **`.wem` байт-в-байт** | работает; WEM→Ogg для `vorbis-wwise` не делаем (помечается) |
| **generic** | — | полный индекс, энтропия, улики движка, zip | копирование + zip | работает |

### Doctor Mode (врачебный аудит)

```bash
salvage audit game/            # doctor включён по умолчанию
salvage scan game/ --doctor    # только скан + doctor
```

Считает «здоровье» проекта 0–100 и проверяет:

- битые заголовки изображений и аудио, пустые файлы;
- PNG с нулевыми/огромными размерами (частая порча при моддинге);
- контейнеры без прочитанного содержимого;
- битые ссылки, дубликаты, зашифрованные блоки;
- инвентарь чувствительных строк (отдельно от doctor, в отчёте).

### Общие анализаторы

- дубликаты по `sha256` и «сколько занимают лишние копии»;
- **битые ссылки**: зависимости контейнеров/сцен → отсутствующие файлы;
- высокая энтропия (возможное шифрование/упаковка);
- инвентарь потенциально чувствительных строк (`apiKey`, токены, приватные ключи, firebase, IP);
- топ самых тяжёлых файлов.

## Форматы отчётов

- `report.html` — автономный (без внешних ресурсов), терминальный стиль;
- `scan.json` — машиночитаемый полный дамп (`totals`, `assets`, `findings`, `meta`, `extraction`);
- `report.md` — для PR/issue;
- `manifest.json` (GameMaker) — все извлечённые ресурсы + объекты/комнаты/скрипты/шейдеры/шрифты;
- `strings.txt` (GameMaker) — все строки игры.

## Коды возврата CLI (для CI)

| Код | Значение |
|---|---|
| 0 | чисто или только `info` |
| 1 | есть предупреждения |
| 2 | есть ошибки |
| 3 | сбой выполнения |

## Архитектура

```
salvage/
├── core/
│   ├── model.py         # Asset, Finding, Dataset
│   ├── plugin_base.py   # контракт EnginePlugin (detect/scan/extract)
│   ├── registry.py      # реестр движков, автодетект
│   ├── scan.py          # оркестратор скана
│   ├── analyze.py       # дубликаты, ссылки, энтропия, секреты
│   ├── doctor.py        # врачeбный отчёт
│   ├── imaging.py       # QOI/PNG кодеки + BZ2 (без зависимостей)
│   ├── ruby_marshal.py  # Ruby Marshal 4.8 → JSON и обратно
│   ├── rpyc.py          # разбор/декомпиляция Ren'Py .rpyc
│   └── util.py          # классификация, магия, sha256, safe_rel
├── plugins/
│   ├── unity/  godot/  gamemaker/  rpgmaker/  renpy/  generic/
│   │   └── generic/: unreal_pak.py, fmod_fsb.py
├── report/              # html / json / md
├── web.py               # локальный пульт (http.server)
└── cli.py               # argparse-интерфейс
```

Плагин обязан реализовать `slug`, `display_name`, `detect()`, `scan()`; `extract()` — опционально.
Ядро не знает ни одного имени движка: всё через реестр.

### Новый движок за 60 строк

```python
# salvage/plugins/mygame/plugin.py
class MyGamePlugin(EnginePlugin):
    slug, display_name, can_extract = "mygame", "MyGame Engine", True

    def detect(self, root):
        return (0.9, ["найден .mygame"]) if (root / "data.mygame").exists() else (0.0, [])

    def scan(self, root, ctx):
        ds = Dataset(self.slug, self.display_name, root)
        ds.add_asset("data.mygame", "archive", (root / "data.mygame").stat().st_size)
        return ds
```

Зарегистрируйте класс в `core/registry.py::build_registry()` — отчёты, doctor, дубликаты,
секреты и CLI подхватят его автоматически.

## Лицензия и зависимости

- `salvage` — собственная реализация: парсеры форматов, модели данных, отчёты и CLI
  написаны с нуля в этом репозитории.
- Глубокий Unity-разбор может использовать **[UnityPy](https://github.com/K0lb3/UnityPy)**
  (MIT) — только как опциональную зависимость (`pip install salvage[unity]`).
- Лицензия `salvage` — MIT. Используйте только на своих или явно разрешённых сборках.

## Roadmap

См. **[ROADMAP.md](ROADMAP.md)** — декомпилятор GML, `.utoc/.ucas` и Oodle, Wwise-банки,
RGSS v2, полный декомпилятор Ren'Py, SARIF для CI.
