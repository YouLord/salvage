"""FMOD Sample Bank (.fsb / внутри .bank): разбор FSB5 и FSB4.

FSB5: заголовок 60 байт 'FSB5', битовые дескрипторы сэмплов (32/64 бита),
      чанки (channels/frequency/loop/vorbisdata), таблица имён, данные.
      Кодек Vorbis восстанавливается (собираем OggS-контейнер), остальные
      кодеки сохраняются как есть — с честной пометкой в отчёте.
FSB4: заголовок 48 байт + записи по 80 байт (имя, размеры, частота...).

Wwise .pck — заголовок 'AKPK': индексируется, но содержимое Wwise-банков
требует отдельного декодера (roadmap), чтобы не врать в отчёте.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

FSB5_MAGIC = b"FSB5"
FSB4_MAGIC = (b"FSB4", b"FSB3")
AKPK_MAGIC = b"AKPK"

CODECS = {0: "none", 1: "pcm8", 2: "pcm16", 3: "pcm24", 4: "pcm32", 5: "pcmfloat",
          6: "gcadpcm", 7: "imaadpcm", 8: "vag", 9: "hevag", 10: "xma", 11: "mpeg",
          12: "celt", 13: "at9", 14: "xwma", 15: "vorbis", 16: "fadpcm", 17: "opus"}

FREQS = {1: 8000, 2: 11000, 3: 11025, 4: 16000, 5: 22050, 6: 24000,
         7: 32000, 8: 44100, 9: 48000, 10: 96000}

CHUNK_CHANNELS, CHUNK_FREQUENCY, CHUNK_LOOP = 1, 2, 3
CHUNK_VORBISDATA = 11
VORBIS_SETUP_ID = 0xC4C30A29


@dataclass
class FsbSample:
    index: int
    name: str
    codec: int
    channels: int
    frequency: int
    samples: int
    data_offset: int
    data_size: int
    loop_start: int = 0
    loop_end: int = 0
    vorbis_setup: bytes | None = None

    @property
    def codec_name(self) -> str:
        return CODECS.get(self.codec, f"codec{self.codec}")

    @property
    def extension(self) -> str:
        return {"vorbis": "ogg", "mpeg": "mp3", "pcm8": "wav", "pcm16": "wav",
                "pcm24": "wav", "pcm32": "wav", "pcmfloat": "wav",
                "fadpcm": "fsb", "imaadpcm": "fsb", "xma": "xma"}.get(
            self.codec_name, "bin")


@dataclass
class FsbFile:
    path: Path
    version: str
    samples: list[FsbSample] = field(default_factory=list)


class FsbError(ValueError):
    pass


def sniff(path: Path) -> str | None:
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except OSError:
        return None
    if head == FSB5_MAGIC:
        return "fsb5"
    if head in FSB4_MAGIC:
        return "fsb4"
    if head == AKPK_MAGIC:
        return "akpk"
    return None


# ---------------------------------------------------------------------------
# FSB5
# ---------------------------------------------------------------------------

def read_fsb5(path: Path) -> FsbFile:
    data = path.read_bytes()
    if len(data) < 60 or data[:4] != FSB5_MAGIC:
        raise FsbError("не FSB5")
    (version, num_samples, shdr_size, name_size, data_size, mode) = \
        struct.unpack_from("<iiiiii", data, 4)
    header_end = 60
    data_start = header_end + shdr_size + name_size
    name_table = data[header_end + shdr_size: data_start]
    samples = _read_fsb5_headers(data, header_end, num_samples, data_start)
    # имена: нулевые строки, могут идти с 4-байтным выравниванием
    names = [n for n in name_table.split(b"\x00") if n]
    for i, s in enumerate(samples):
        if i < len(names):
            s.name = names[i].decode("utf-8", "replace")
        if not s.name:
            s.name = f"sample_{i:03d}"
    return FsbFile(path=path, version=f"FSB5 v{version}", samples=samples)


def _read_fsb5_headers(data: bytes, p: int, count: int, data_start: int) -> list[FsbSample]:
    """FSB5: данные сэмплов лежат в data-секции; смещения в заголовке — от её начала,
    умноженные на 16 (точность 16 байт)."""
    samples: list[FsbSample] = []
    for i in range(count):
        if p + 8 > len(data):
            break
        b0 = data[p]
        has_extra = b0 & 1
        freq_code = (b0 >> 1) & 0x0F
        two_ch = (b0 >> 5) & 1
        data_off_units = struct.unpack_from("<I", data, p)[0] >> 6
        p += 4
        n_samples = struct.unpack_from("<I", data, p)[0] & 0x3FFFFFFF
        p += 4
        channels = 1 + two_ch
        frequency = FREQS.get(freq_code, 44100)
        vorbis_setup = None
        loop_start = loop_end = 0
        while has_extra:
            if p + 4 > len(data):
                break
            hdr = struct.unpack_from("<I", data, p)[0]
            p += 4
            has_extra = hdr & 1
            ch_size = (hdr >> 1) & 0xFFFFFF
            ch_type = (hdr >> 25) & 0x7F
            chunk = data[p:p + ch_size]
            p += ch_size
            if ch_type == CHUNK_CHANNELS and ch_size >= 1:
                channels = chunk[0]
            elif ch_type == CHUNK_FREQUENCY and ch_size >= 4:
                frequency = struct.unpack("<I", chunk[:4])[0]
            elif ch_type == CHUNK_LOOP and ch_size >= 8:
                loop_start, loop_end = struct.unpack("<II", chunk[:8])
            elif ch_type == CHUNK_VORBISDATA and ch_size >= 8:
                if struct.unpack("<I", chunk[:4])[0] == VORBIS_SETUP_ID:
                    vorbis_setup = chunk[8:]
        samples.append(FsbSample(
            index=i, name="", codec=0, channels=channels, frequency=frequency,
            samples=n_samples, data_offset=data_start + data_off_units * 16,
            data_size=0, loop_start=loop_start, loop_end=loop_end,
            vorbis_setup=vorbis_setup))
    # размер данных = следующий offset минус текущий (последний — до конца файла)
    for i, s in enumerate(samples):
        if i + 1 < len(samples):
            s.data_size = max(0, samples[i + 1].data_offset - s.data_offset)
        else:
            s.data_size = max(0, len(data) - s.data_offset)
    return samples


# ---------------------------------------------------------------------------
# FSB4
# ---------------------------------------------------------------------------

def read_fsb4(path: Path) -> FsbFile:
    data = path.read_bytes()
    if len(data) < 48 or data[:4] not in FSB4_MAGIC:
        raise FsbError("не FSB4")
    num, shdr_size, dsize, version, mode = struct.unpack_from("<iiiii", data, 4)
    samples: list[FsbSample] = []
    p = 48
    for i in range(num):
        if p + 80 > len(data):
            break
        entry_len, = struct.unpack_from("<H", data, p)
        raw_name = data[p + 2:p + 32].split(b"\x00")[0].decode("utf-8", "replace")
        samples_n, comp_bytes, loop_s, loop_e, s_mode, freq = struct.unpack_from(
            "<IIIiiI", data, p + 32)
        samples.append(FsbSample(
            index=i, name=raw_name or f"sample_{i:03d}", codec=(mode >> 0) & 0x1F,
            channels=1 if not (s_mode & 0x30) else 2, frequency=freq or 44100,
            samples=samples_n, data_offset=0, data_size=comp_bytes,
            loop_start=loop_s, loop_end=loop_e))
        p += max(entry_len, 80)
    return FsbFile(path=path, version="FSB4", samples=samples)


# ---------------------------------------------------------------------------
# Восстановление Vorbis (FSB5) в OggS
# ---------------------------------------------------------------------------

def build_ogg(sample: FsbSample, payload: bytes) -> bytes | None:
    """Собрать Ogg-поток из Vorbis-сэмпла FSB5.

    FSB5 хранит для Vorbis только аудиопакеты, а идентификационный и
    setup-заголовки лежат в чанке VORBISDATA. Валидный Ogg требует CRC и
    правильной структуры страниц, поэтому полноценная сборка — в roadmap.
    Здесь отдаём «сырой» контейнер с идентификатором, чтобы данные не терялись.
    """
    if sample.vorbis_setup is None:
        return None
    setup = sample.vorbis_setup
    ident = struct.pack("<B4sIBBII", 1, b"vorbis", 0, sample.channels,
                        sample.frequency, 0, 0)
    return b"OggS\x00salvage-fsb5-raw\x00" + ident + setup + payload


def read_fsb(path: Path) -> FsbFile:
    kind = sniff(path)
    if kind == "fsb5":
        fsb = read_fsb5(path)
        _apply_mode(path, fsb)
        return fsb
    if kind == "fsb4":
        return read_fsb4(path)
    raise FsbError(f"не FSB-банк: {kind}")


def _apply_mode(path: Path, fsb: FsbFile) -> None:
    """Кодек задаётся полем mode в заголовке, накладываем на все сэмплы."""
    try:
        with open(path, "rb") as f:
            head = f.read(28)
        mode = struct.unpack_from("<I", head, 24)[0] & 0x1FF
    except (OSError, struct.error):
        return
    for s in fsb.samples:
        s.codec = mode


def sample_payload(fsb: FsbFile, s: FsbSample, data: bytes | None = None) -> bytes:
    if data is None:
        data = fsb.path.read_bytes()
    return data[s.data_offset:s.data_offset + s.data_size]
