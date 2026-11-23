"""Стенд FMOD-Vorbis: настоящий libvorbis-поток, упакованный как FSB5.

Зачем отдельная фикстура: FSB5-Vorbis хранит только аудиопакеты (каждый с
uint16-длиной) и таблицу seek; setup-заголовок идёт в чанке VORBISDATA, а
блоксайзы нигде не лежат — их приходится проверять декодированием. На такой
фикстуре видно разницу между «файл похож на ogg» и «файл звучит».

Требует `soundfile` (libsndfile) на этапе СОЗДАНИЯ фикстуры; при отсутствии
модуль помечает стенд как недоступный и создаёт пустую папку.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixture_base import ensure_dir

SAMPLE_RATE = 22050
DURATION = 0.6


def _make_reference_ogg() -> bytes | None:
    try:
        import io
        import numpy as np
        import soundfile as sf
    except Exception:
        return None
    n = int(SAMPLE_RATE * DURATION)
    t = np.linspace(0, DURATION, n, endpoint=False)
    wave = (0.4 * np.sin(2 * np.pi * 440 * t) + 0.25 * np.sin(2 * np.pi * 660 * t)
            + 0.1 * np.sin(2 * np.pi * 880 * t))
    wave *= 0.5 + 0.5 * np.sin(2 * np.pi * 3 * t)
    pcm = (wave * 16000).astype(np.int16)
    buf = io.BytesIO()
    sf.write(buf, pcm, SAMPLE_RATE, format="OGG", subtype="VORBIS")
    return buf.getvalue()


def build(root: Path, *, with_bug: bool = False) -> Path:
    ensure_dir(root)
    from salvage.core import ogg

    ref = _make_reference_ogg()
    (root / "reference.ogg").write_bytes(ref or b"")
    if ref is None:
        (root / "SKIP").write_text("soundfile недоступен", "utf-8")
        return root
    pages = ogg.parse_pages(ref)
    ident = pages[0].segments[0]
    setup = pages[1].segments[1]
    audio = [pkt for page in pages[2:] for pkt in page.segments]
    total_samples = int(pages[-1].granule)

    # --- упаковка в FSB5 ---
    payload = b"".join(struct.pack("<H", len(p)) + p for p in audio) + b"\x00\x00"
    # чанк VORBISDATA: uint32 setup_id, uint32 seek-таблица (0), setup-пакет
    setup_chunk = (struct.pack("<I", 0xC4C30A29) + struct.pack("<I", 0)
                   + setup)
    extra = struct.pack("<I", (11 << 25) | (len(setup_chunk) << 1) | 0) + setup_chunk
    mode = (1 << 1)            # частота 8000? нет: код 1 = 8000; ниже перезапишем частотой кода 8
    mode = (0x08 << 1)         # 44100 (код 8)
    mode |= 0                  # 1 канал
    mode |= (0 << 7)           # смещение данных 0
    mode |= (total_samples << 34)
    # у сэмпла есть extra-чанки => поднимаем бит 0 и меняем частоту на 22050 (код 5)
    mode &= ~((0x0F) << 1)
    mode |= (0x05 << 1) | 1
    sample_hdr = struct.pack("<Q", mode) + extra
    # таблица имён: один офсет + строка
    name_table = struct.pack("<I", 4) + b"vorbis_theme\x00"
    mode_field = 15  # FMOD_SOUND_FORMAT_VORBIS
    hdr = (b"FSB5" + struct.pack("<iiiiii", 1, 1, len(sample_hdr),
                                 len(name_table), len(payload), mode_field)
           + b"\x00" * 8 + b"\x00" * 16 + b"\x00" * 8)
    assert len(hdr) == 0x3C
    (root / "VorbisMusic.bank").write_bytes(hdr + sample_hdr + name_table + payload)
    meta = {
        "samples": total_samples,
        "frequency": SAMPLE_RATE,
        "audio_packets": len(audio),
        "reference_sha256": __import__("hashlib").sha256(ref).hexdigest(),
    }
    (root / "expected_vorbis.json").write_text(json.dumps(meta, indent=1), "utf-8")
    return root


BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError


# ---------------------------------------------------------------------------
# Упаковка произвольного Ogg-Vorbis в FSB5 (для сквозного теста с реальным файлом)
# ---------------------------------------------------------------------------

FREQ_CODES = {8000: 1, 11000: 2, 11025: 3, 16000: 4, 22050: 5, 24000: 6,
              32000: 7, 44100: 8, 48000: 9}


def pack_ogg_into_fsb(ogg_bytes: bytes, *, samples: int) -> bytes:
    """Собрать FSB5 v1 из готового Ogg-Vorbis.

    FSB5 хранит тождественную идентификацию, setup в чанке VORBISDATA
    (0xC4C30A29 + uint32 размер + setup) и аудиопакеты [uint16 len][packet].
    Comment в банке не хранится — при обратной сборке он синтезируется.
    """
    from salvage.core import ogg as oggmod

    pages = oggmod.parse_pages(ogg_bytes)
    packets = [pkt for page in pages for pkt in page.packets]
    if len(packets) < 4:
        raise ValueError("в Ogg меньше трёх заголовков + аудио")
    ident, setup = packets[0], packets[2]
    audio = packets[3:]
    channels = ident[11]
    rate = struct.unpack_from("<I", ident, 12)[0]
    code = FREQ_CODES.get(rate)
    if code is None:
        raise ValueError(f"частота {rate} не кодируется в FSB5")

    payload = b"".join(struct.pack("<H", len(p)) + p for p in audio) + b"\x00\x00"
    setup_chunk = struct.pack("<I", 0xC4C30A29) + struct.pack("<I", 0) + setup
    # extra-чанк: тип 11 в битах 25.., размер — в битах 1..
    extra = struct.pack("<I", (11 << 25) | (len(setup_chunk) << 1)) + setup_chunk
    mode = (samples << 34) | (code << 1) | ((channels - 1) << 5) | 1
    sample_hdr = struct.pack("<Q", mode) + extra
    name = b"tone\x00"
    name_table = struct.pack("<I", 4) + name
    hdr = (b"FSB5" + struct.pack("<iiiii", 1, 1, len(sample_hdr), len(name_table),
                                 len(payload))
           + struct.pack("<II", 15, 0))          # кодек Vorbis
    hdr += b"\x00" * (0x3C - len(hdr))
    assert len(hdr) == 0x3C, len(hdr)
    return hdr + sample_hdr + name_table + payload
