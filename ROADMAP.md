# Roadmap salvage

Сортировано по соотношению «польза / трудозатраты». Статусы честные: ❌ нет, 🟡 частично, ✅ есть.

---

## Политика отчёта: «честная ошибка» vs «тихо неправильно»

Это главный принцип инструмента, и он зафиксирован как приёмочный критерий:

- **Честная ошибка (допустимо).** Инструмент говорит «не умею / не прочитал / пропущено», пишет
  статус в `scan.json` (`skipped` с причиной `encrypted`, `compression:N`, `unsupported:…`) и в
  findings. Ничего не выдумывает. Пользователь видит ровно то, что произошло.
- **Тихо неправильный результат (недопустимо).** Инструмент выдаёт файл, который выглядит как
  рабочий, но внутри — мусор: «сырой» контейнер под именем `.ogg`, обрезанные данные из-за лимита,
  неполный скан, показанный как «всё чисто», частичное извлечение без пометки. На **каждый такой
  случай должен быть отдельный тест**, который ловит именно его. Такие тесты помечены в коде
  префиксом `test_never_silently_*` и собраны в `tests/test_honesty.py`.

Правила, вытекающие из политики (действуют для всех движков):

| Правило | Что проверяет машина |
|---|---|
| «Сырой»/недоделанный контейнер не получает рабочее расширение | `test_never_silently_raw_as_ogg`, `test_wwise_wem_status` |
| Частичное извлечение ≠ успех | `test_never_silently_partial_extract`, `test_cli_partial_extract_exit_code` |
| Лимиты делают скан неполным и это видно в отчёте | `test_never_silently_truncated_scan_hidden` |
| Битый заголовок → файл не пишется «как валидный» | `test_never_silently_bad_payload` |
| Неизвестный/изменённый формат → явный `unsupported`, не догадка | `test_never_silently_unknown_format` |
| Идемпотентность extract: повтор = те же байты, не «второй набор» | `test_extract_idempotent` |
| Смена схемы `scan.json` не ломает старый код молча | `test_schema_version_present`, `test_schema_backcompat_keys` |

---

## Критерии приёмки 0.2 (стенд → тест → ожидаемый результат)

Формат: **пункт — стенд — тест — что считается успехом** (байт-в-байт / размер / хэш / наличие
секции). Все тесты ниже входят в `python -m unittest discover tests` и зелёные на стенде.

### GameMaker

| Пункт 0.2 | Стенд | Тест | Ожидаемый результат |
|---|---|---|---|
| SPRT → TPAG → TXTR, кадры спрайтов | `fixtures/gm` (SPRT 1 спрайт, TPAG 4 ректа) | `test_gamemaker_extract_textures_audio_manifest` | ровно 2 файла `sprites/spr_player_00.png`, `_01.png`; каждый **байт-в-байт** равен вырезанному rect из страницы (`test_gm_sprite_frames_byte_exact`) |
| Текстуры PNG/QOI/BZ2, экспорт в PNG | `fixtures/gm` (3 страницы: png, qoi, bz2+qoi) | `test_qoi_png_codecs`, `test_gamemaker_extract_textures_audio_manifest` | `textures/tex_000..002.png`; для QOI-страницы RGBA **побайтово** совпадает с эталонным массивом пикселей (`test_gm_texture_qoi_roundtrip_exact`) |
| Экспорт текстур в qoi/bz2 | `fixtures/gm` | `test_gm_texture_export_formats` | `--texture-format qoi` → файлы с магией `qoif`, декодируются обратно в те же пиксели; `bz2` → `BZh` + QOI |
| Аудио из встроенного AUDO | `fixtures/gm` | `test_gamemaker_extract_textures_audio_manifest` | `audio/sn_click.ogg` начинается с `OggS`, размер == исходному блобу |
| Аудио из внешней `audiogroup1.dat` | `fixtures/gm` | `test_gamemaker_extract_textures_audio_manifest`, `test_gm_external_audiogroup` | `audio/sn_music.ogg` есть, байт-в-байт равен блобу из `audiogroup1.dat` |
| `manifest.json` + имена объектов/комнат/скриптов/шейдеров | `fixtures/gm` | `test_gamemaker_chunks`, `test_gamemaker_extract_textures_audio_manifest` | в манифесте `objects==["obj_player"]`, `rooms==["rm_room"]`, `scripts==["scr_move"]`, `shaders==["sh_pass"]`, `counts.textures==3`, `counts.sprites==1` |
| `strings.txt` | `fixtures/gm` (8 строк) | `test_gamemaker_chunks` | ≥8 строк, есть `spr_player`, `sn_music` |

### RPG Maker (XP/VX/Ace + MV/MZ)

| Пункт 0.2 | Стенд | Тест | Ожидаемый результат |
|---|---|---|---|
| RGSSAD v1 расшифровка | `fixtures/rm_xp/Game.rgssad` (4 записи) | `test_rgss_v1_v3` | 4 записи; данные **байт-в-байт** равны исходным (`test_rgss_v1_byte_exact` сверяет sha256 с эталоном) |
| RGSS3A v3 расшифровка | `fixtures/rm_xp/Game.rgss3a` (3 записи) | `test_rgss_v1_v3` | 3 записи; PNG начинается с `\x89PNG`, OGG — с `OggS` |
| Конвертация `.rxdata/.rvdata2` → JSON | `fixtures/rm_xp/Data/*` | `test_rpgmaker_data_json` | `data_json/Data/Actors.rxdata.json`, `__class__=="RPG::Actor"`, кириллица `"Герой"` сохранена |
| MV/MZ расшифровка | `fixtures/rm_mv` | `test_mv_decrypt`, `test_mv_extract_roundtrip` | 16-байтный XOR обратим **побайтово**; извлечённые `.png` с магией PNG, `.ogg` с `OggS` |
| Аудит показывает шифрование | `fixtures/rm_mv` | `test_mv_extract_roundtrip` | у ассетов `extra.encrypted` заполнен; в JSON-отчёте `encrypted` виден |

### Ren'Py

| Пункт 0.2 | Стенд | Тест | Ожидаемый результат |
|---|---|---|---|
| Распаковка `.rpa` | `fixtures/renpy/*.rpa` (3 файла) | `test_renpy_rpa` | 3 файла из RPA, `bg room.png` и `theme.ogg` на месте; `.rpa` не копируется дважды |
| Декомпиляция `.rpyc` (RPC2) | `fixtures/renpy/game/compiled.rpyc` | `test_rpyc_decompile` | `decompiled/game/compiled.rpyc.rpy`: есть `label start:`, реплика, имя экрана `main_menu` |
| Декомпиляция `.rpyc` (старый zlib) | `fixtures/renpy/game/script.rpyc` | `test_rpyc_decompile` | второй файл `.rpy` тоже создан, содержит строку из AST |
| Doctor: здоровье проекта | `fixtures/renpy` + битая мини-игра | `test_doctor_mode` | score < 100, `bad_images==1`, `empty==1`, в MD есть «Врачебный отчёт» |

### Универсальный режим

| Пункт 0.2 | Стенд | Тест | Ожидаемый результат |
|---|---|---|---|
| UE `.pak` v1–v11, zlib-блоки | `fixtures/ue` (v3, 3 записи) | `test_unreal_pak` | v3, 3 записи, сжатие `["zlib"]`, извлечённые файлы **байт-в-байт** равны исходным (`test_ue_pak_byte_exact`) |
| FMOD `.fsb/.bank` | `fixtures/fmod` (FSB5, 3 сэмпла) | `test_fmod_fsb5` | 3 сэмпла, кодек `pcm16`, извлечено 3 файла |
| Wwise `.pck` индексируется | `fixtures/wwise_pck` | `test_wwise_pck_index` | в `meta["wwise_pck_data"]` 2 записи, `wem`-id совпадают |
| Автодетект по сигнатурам | все `fixtures/*` | `test_detect_all_engines` | для каждого стенда `best_engine` == ожидаемый slug |
| Единый отчёт JSON/HTML/MD | `fixtures/gm`, `fixtures/rm_xp` | `test_reports`, `test_cli_audit_doctor_report` | `scan.json` с `schema_version`; в HTML секция «Врачебный отчёт»; в MD заголовок «# Аудит» |
| Дубликаты/энтропия/секреты | `fixtures/unity` | `test_unity_deep_degrades_gracefully` | `meta.secrets.api_key` найден по `settings.json` |

### Сквозные инварианты

| Инвариант | Тест |
|---|---|
| Скан не падает ни на одном стенде (0/1/2, не 3) | `test_cli_scan_exit_codes`, `test_cli_audit_doctor_report` |
| Пути из архивов не выходят за `--out` (`../../`) | `test_safe_rel_blocks_traversal` + `test_never_silently_path_traversal` |
| `extract` идемпотентен | `test_extract_idempotent` |
| HTML не тянет внешние ресурсы | `test_web_html_selfcontained` |

Статус на 2026-11-23: **все пункты 0.2 выше закрыты тестами**; при этом сам факт «пункт есть» не
равен «пункт полный» — незакрытые части (GML, Oodle, Wwise-декодер) перечислены в ограничениях
ниже и в приоритетах.

---

## Сделано в 0.2

| Область | Статус |
|---|---|
| **GameMaker: спрайты SPRT → TPAG → TXTR** с rect-манифестом и нарезкой кадров (Pillow, опционально) | ✅ |
| **GameMaker: текстуры PNG / QOI / BZ2(+QOI/PNG)** — собственный QOI-декодер/кодер, экспорт в png/qoi/bz2 | ✅ |
| **GameMaker: аудио из встроенного AUDO + внешних `audiogroup*.dat`**, сопоставление SOND (имя/группа/audio_id) | ✅ |
| **GameMaker: `manifest.json`** — ресурсы + объекты/комнаты/скрипты/шейдеры/шрифты + `strings.txt` | ✅ |
| **RPG Maker XP/VX/Ace: RGSSAD v1 и v3** — разбор индекса и расшифровка потоков (v2 не нужен как формат: VX пишет версию 1) | ✅ |
| **RPG Maker: конвертация `.rxdata/.rvdata2` → JSON** (собственный Ruby Marshal 4.8, без Ruby; round-trip) | ✅ |
| **Ren'Py: распаковка RPA** (уже было) + **декомпиляция `.rpyc`** (RPC2 и старый zlib-формат) в приближённый `.rpy` | ✅ |
| **Ren'Py: Doctor Mode** — целостность медиа, дубликаты, битые ссылки, оценка 0–100 | ✅ |
| **Unreal `.pak` v1–v11** — footer/индекс/записи, zlib-блоки, пометка AES и методов сжатия | ✅ |
| **FMOD `.fsb/.bank`** FSB5/FSB4 — индексирование и извлечение сэмплов | ✅ (Vorbis — «сырой» контейнер, см. 0.3) |
| **Wwise `.pck` (AKPK)** — индексирование, честная пометка «декодер в roadmap» | 🟡 → ✅ в 0.3 |
| **Единый отчёт** — scan + extract + doctor в одном HTML/JSON/MD, извлечённые файлы в дампе | ✅ |
| **Автодетект** — реестр плагинов по сигнатурам (`GDPC`, `RPA`, `data.win`, `RGSSAD`, `.pak`, `FSB5`...) | ✅ |
| Дубликаты, энтропия, секреты, битые ссылки | ✅ (было в 0.1) |

## Сделано в 0.3

Что считается сделанным — только то, у чего есть стенд и тест.

| Область | Статус | Чем подтверждено |
|---|---|---|
| **RGSS v2 (`.rgss2a`)** — VX объявляет версию 1; явная поддержка + тест | ✅ | `test_regressions` (RGSS v1/v2/v3, байт-в-байт), `make_fixture_rpgmaker_xp.py` |
| **Wwise `.pck` (AKPK)** → `.wem`, **`.bnk` (BKHD/DIDX/DATA)** → `.wem` | ✅ | `make_fixture_wwise.py`; `test_wwise.py`: индекс, sha256 каждого wem, сквозной extract |
| **Vorbis Wwise не маскируется под `.ogg`**: `vorbis-ogg-like` → `.ogg`, `vorbis-wwise`/прочие → `.wem` со статусом | ✅ | `test_wwise.py`, статусы в `meta.wwise_wem_status` и в summary |
| **FMOD FSB5 Vorbis** → валидный OggS (CRC, granule, serial; подбор блоксайза декодером) | ✅ | `make_fixture_fmod_vorbis.py` (libvorbis → FSB5 → Ogg, corr 1.0 при наличии `soundfile`); без декодера — статус `decode-silent`/`structural-only` |
| **FSB5-раскладка** (samples 63..34, offset ×32, база 0x3C/0x40) | ✅ | `test_fmod_vorbis.py` / `make_fixture_fmod.py`: payload 96/128/96, data_offset 123/219/347 |
| **UE `.pak` LZ4-блоки** (метод 0x10) | ✅ | `make_fixture_unreal_lz4.py` (v8, методы None/Zlib/LZ4/Oodle), `test_unreal_lz4.py`: sha256 байт-в-байт |
| **UE `.pak`: семантика offset записи** (offset → заголовок записи, данные после него; блоки абсолютные) | ✅ | регресс-тест `test_regression_ue_offset_semantics` + пересобранная фикстура `ue` (v3) |
| **CLI/отчёты**: коды возврата, идемпотентность extract, видимые лимиты, `--engine` (форс/авто/generic) | ✅ | `test_cli_contract.py` (17 тестов) |
| **Doctor `score_breakdown`** в JSON, MD и HTML; `score = 100 + Σ штрафов` | ✅ | `test_doctor_breakdown_in_json_and_md` |
| **`schema_version` в `scan.json`** + политика совместимости | ✅ | `test_scan_json_has_schema_version`; политика — ниже |
| **Веб-пульт/HTML:** автономность (без внешних http-ресурсов) | ✅ | `test_html_is_self_contained` |

Итого тестов: `python -W ignore -m unittest discover -s tests` — **64 OK**.

### schema_version и обратная совместимость

`scan.json` начинается с `schema_version` (сейчас **1**) и `generator_version`.
Политика:

- **Добавление полей — не новая версия.** Потребитель обязан игнорировать незнакомые поля.
- **Удаление/переименование/смена типа/смысла поля — новая версия.** Такие правки идут
  только с обновлением этого раздела и записи в «Сделано».
- Потребителю, который не знает `schema_version`, рекомендовано читать по белому списку
  и падать с явной ошибкой, а не заполнять поля по догадке.
- SARIF-вывод (приоритет 3) появится **после** стабилизации схемы.

---

## Unreal .pak: семантика поля method (зафиксировано)

Разбор `.pak` без догадок — метод разрешается строго по конвенции версии.

| Версия pak | Что лежит в поле method | Разрешение |
|---|---|---|
| 1–7 | legacy-биты `ECompressionFlags` | 0 — none, 0x01 — zlib, 0x02 — gzip, 0x04 — custom (кодек игры, обычно Oodle), 0x10 — bias-memory, 0x20 — bias-speed |
| 8+ | индекс в таблице имён из footer | Основная конвенция **1-based**: `method=1 → names[0]`. Если `names[0]` явно `None`/`-`/пусто, таблица нумеруется **с нуля**: `method → names[method]` |
| 8+ без таблицы имён | индекс без имён | не угадывается → `compression:0xNN`, данные = `None` |

Плюрализм конвенций не «на глаз»: способ нумерации — свойство самой таблицы
(`_table_is_zero_based`), поэтому все записи пака читаются одинаково.
Покрыто `tests/test_unreal_lz4.py::TestMethodConventions` (1-based, 0-based,
legacy-биты, отсутствие таблицы).

**Сжатие.** LZ4 в `.pak` — raw block-формат (не frame): свой декодер
`salvage/core/lz4.py` без обязательных зависимостей, сверка с `lz4.block`
в тесте (`skipUnless`). Oodle — `compression:oodle`, без попыток декодирования:
статус виден в `meta.ue_pak_statuses` и в summary извлечения.

**Точность seek.** Для FSB5 Vorbis промежуточные granule = -1: это легально
по спецификации Ogg, но **точный seek по времени приблизительный** —
плеер сможет перемотать по страницам, а не по сэмплам.

## FSB5 Vorbis: структура VORBISDATA (зафиксировано)

```
VORBISDATA = uint32 setup_id (0xC4C30A29) | uint32 размер setup | setup-пакет («\x05vorbis»…)
аудиоданные = ([uint16 длина][пакет])* , конец — длина 0 или 0xFFFF
```

Если setup_id не совпал, размер не сходится или setup не начинается с `\x05vorbis`,
конвертация **не выполняется**: статус `headers-unrecoverable` с причиной в
`reason`, файл остаётся `.wem`/сырым FSB-пейлоадом. «Сырой контейнер под видом .ogg»
запрещён — это тот самый тихо неправильный результат.

Доказательство работоспособности (без внешних утилит):
`tests/test_fmod_tone.py` берёт реальный `tests/assets/tone.ogg` (коммитится),
разбирает его на заголовки и пакеты, собирает FSB5, извлекает обратно в Ogg:
свой парсер проверяет CRC/sequence/serial/BOS/EOS/granule, а `soundfile`
(`skipUnless`) декодирует и сверяет PCM — 13230 сэмплов, corr = 1.0.

## Приоритет 1 — доделать начатое

0. **Пункт 3 плана 0.3 закрыт** (RGSS v2 / Wwise WEM / OggS / LZ4) — эпик GML разблокирован.
1. **GameMaker: байткод GML.** Парсер `CODE`/`VARI`/`FUNC` + декомпилятор (v14–17 сначала).
   Самый крупный оставшийся кусок — нужен табличный подход к версиям инструкций.
   **Отдельный эпик: начинать после закрытия п. 3 плана 0.3 (закрыт).**
   Критерии приёмки эпика — ниже, в разделе «Эпик GML».
2. **Unreal: `.utoc/.ucas` (IoStore)** и **Oodle**-сжатие в `.pak` (0x20/`bias`). Oodle лицензирован —
   только подключение внешней библиотеки, без вендоринга; до этого — честный статус `compression:…`.
3. **Wwise HIRC**: события → действия → звуки (граф), плюс `.bnk` с Vorbis/wem-обёртками там,
   где кодек не удаётся определить.
4. **Ren'Py: полный декомпилятор** (эмуляция всех классов `renpy.ast.*`) вместо приближённого `.rpy`:
   восстановление точных операторов `show/hide/menu/jump`.
5. **Unity WebGL / `.data`-распаковка** и источник-движки — см. приоритет 2.

## Эпик GML (после 0.3)

Табличный подход: на каждую версию байткода — таблица `opcode → (имя, арность, типы операндов)`.

| Шаг | Стенд | Тест | Ожидаемый результат |
|---|---|---|---|
| Чанк `CODE` → байткод-блоки | реальные `data.win` v14–17 | адреса/длины блоков | байт-в-байт с `len(code)` из `STRG`-таблиц |
| `VARI`/`FUNC`/`STRG` → имена | фикстуры с известными именами | разрешение ссылок | 100 % имён переменных/функций |
| Дизассемблер (табличный) | «эталонный» скрипт | сравнение с ожидаемым листингом | совпадение строк листинга |
| Декомпилятор (v14–17) | 10 реальных игр | сравнение с GML из открытых исходников | совпадение поведения, не обязательно текста |

Честность: если версия неизвестна или opcode не в таблице — **стоп с ошибкой**,
а не «правдоподобный» GML.

## Приоритет 2 — новые движки

6. **Cocos2d-x / Laya / Egret**: APK-контейнер, `assets/src/*.jsc` (XOR `88 16 33 12`), `.ccz/.pkm`, `.luac`.
7. **Source/Unity WebGL**: `.vpk`/`.bsp`, `.data`/`.wasm`.
8. **Construct 3 / Clickteam Fusion** — малые форматы, быстрые победы.

## Приоритет 3 — инфраструктура и UX

9. **SARIF-вывод** отчёта для GitHub Code Scanning (CI-гейт на битые ссылки/секреты) — после
   стабилизации `schema_version`.
10. **Инкрементальный кэш скана** (sqlite) — повторный скан больших сборок 10× быстрее.
11. **Diff двух сборок**: что добавилось/удалилось/изменилось.
12. **Экспорт-профили**: «только текстуры в PNG», «только звук», «только локализация».
13. **Плагин-корреляции**: ассеты ↔ сцены ↔ скрипты.
14. **Авторедакция отчётов**: маска ключей, allowlist/denylist путей.
15. **Локализация CLI/отчётов**: ru/en (сейчас ru).

## Известные ограничения

- **GameMaker**: байткод GML не декомпилируется; формат TPAG/SPRT стабилен, но записи
  новых версий (v18+) могут отличаться на пару полей — парсер терпим к сдвигам и пишет rect в манифест.
  Шрифты (FONT) видны в карте чанков, но в `manifest.json` пока не выгружаются.
- **Ren'Py**: `.rpyc` декомпилируется «мягко» (метки/экраны/реплики/строки), а не побайтово.
  Защищённые игры (NRP2, изменённые заголовки) дают честную ошибку, а не «тихо неправильный» текст.
- **Unreal**: поддерживаются незашифрованные `.pak` v1–v11, zlib и LZ4-блоки; AES и Oodle — честно
  помечаются и пропускаются. `.utoc/.ucas` не читаются (приоритет 1).
- **RPG Maker**: RGSSAD v1 (он же `.rgss2a`) / v3 и MV/MZ полностью; экзотические патчи архивов
  (Fux2Pack) не поддерживаются — дают ошибку разбора, а не мусор.
- **Wwise**: `.pck` (AKPK v1/v2) и `.bnk` (BKHD/DIDX/DATA) индексируются, `.wem` извлекаются
  байт-в-байт. **Vorbis Wwise (кодек 0xFFFF/0xFFFE) в `.ogg` не конвертируется** — он отдаётся
  как `.wem` со статусом `vorbis-wwise`; `.ogg` пишется только для `vorbis-ogg-like`
  (внутри уже стандартный OggS). HIRC (граф событий/действий) не разбирается — приоритет 1.
- **FMOD Vorbis** собирается в Ogg **структурно** (страницы/CRC/granule/serial валидны);
  совпадение звука подтверждается только при наличии декодера (в тестах — `soundfile`,
  иначе `skipUnless`). Настоящий FSB5 хранит лишь `setup_id` — кодбуки внешние,
  поэтому фикстура вкладывает setup внутрь, а не «подделывает» реальный банк.
- **UE `.pak`**: LZ4-блоки и zlib читаются; **Oodle и AES не поддерживаются** —
  `unsupported:oodle` / `encrypted` в статусах, при извлечении это **ошибка**, а не тихий skip.
  Паки v10/v11 читаются, но encoded-entry разбирается только для одного блока
  (multi-block encoded записи пока дают `error:*`, а не мусор).
- **Лимиты скана** (`max_files` 200k, `.pak` 200, FMOD-банков 300, Unity-контейнеров 300)
  при срабатывании дают `meta.limits` + `meta.truncated: true` + находку `limit_*`;
  скан при этом помечен как неполный, а не выдаётся за полный.
- **`max_asset_bytes`** (16 МиБ по умолчанию, `--max-asset-bytes`) усекает отдельный
  извлекаемый файл; усечение — не ошибка формата, но размер в отчёте будет меньше фактического.
- Инвентарь секретов — эвристика по регуляркам; ложные срабатывания помечаются `info`.
- Экспорт в `/dev/null`, несуществующий `--engine` и т.п. → код 3 и сообщение, без «тихого успеха».
