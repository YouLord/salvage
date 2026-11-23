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

from ...core import ogg

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
    # vgmstream: FSB5 v0 — 0x40 байт заголовка, v1 — 0x3C (есть флаги на 0x20)
    header_end = 0x3C if version == 1 else 0x40
    if len(data) < header_end:
        raise FsbError("обрезанный заголовок FSB5")
    data_start = header_end + shdr_size + name_size
    name_table = data[header_end + shdr_size: data_start]
    if data_start > len(data):
        raise FsbError("FSB5: заголовок/имена выходят за файл")
    samples = _read_fsb5_headers(data, header_end, num_samples, data_start)
    # имена: таблица = uint32 offsets[], каждый офсет от начала name_table
    names = _read_name_table(name_table, len(samples))
    for i, s in enumerate(samples):
        s.name = names[i] if i < len(names) and names[i] else f"sample_{i:03d}"
    return FsbFile(path=path, version=f"FSB5 v{version}", samples=samples)


def _read_fsb5_headers(data: bytes, p: int, count: int, data_start: int) -> list[FsbSample]:
    """FSB5: заголовок сэмпла — одно 64-битное поле + цепочка чанков.

    Раскладка (vgmstream/fsb5.c): биты 0 — extra-флаг, 1..5 — частота,
    6..7 — код каналов (0→1, 1→2, 2→6, 3→8), 8..33 — смещение данных
    в единицах по 32 байта от начала data-секции, 34..63 — число сэмплов.
    """
    samples: list[FsbSample] = []
    for i in range(count):
        if p + 8 > len(data):
            break
        mode = struct.unpack_from("<Q", data, p)[0]
        p += 8
        has_extra = mode & 1
        freq_code = (mode >> 1) & 0x0F
        ch_code = (mode >> 5) & 0x03
        data_off_units = (mode >> 7) & 0x07FFFFFF
        n_samples = (mode >> 34) & 0x3FFFFFFF
        channels = {0: 1, 1: 2, 2: 6, 3: 8}[ch_code]
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
            samples=n_samples, data_offset=data_start + data_off_units * 32,
            data_size=0, loop_start=loop_start, loop_end=loop_end,
            vorbis_setup=vorbis_setup))
    # размер данных = следующий offset минус текущий (последний — до конца файла)
    for i, s in enumerate(samples):
        if i + 1 < len(samples):
            s.data_size = max(0, samples[i + 1].data_offset - s.data_offset)
        else:
            s.data_size = max(0, len(data) - s.data_offset)
    return samples


def _read_name_table(table: bytes, count: int) -> list[str]:
    """Таблица имён FSB5: count × uint32 offset от начала таблицы, строки с NUL."""
    names: list[str] = []
    if len(table) < 4 * count:
        raw = [n for n in table.split(b"\x00") if n]
        return [n.decode("utf-8", "replace") for n in raw][:count]
    for i in range(count):
        off = struct.unpack_from("<I", table, i * 4)[0]
        if off >= len(table):
            names.append("")
            continue
        end = table.find(b"\x00", off)
        end = len(table) if end < 0 else end
        names.append(table[off:end].decode("utf-8", "replace"))
    return names


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

# Блоксайзы Vorbis НЕ хранятся ни в FSB5, ни в setup-заголовке: в
# идентификационном заголовке они обязаны совпадать с теми, которыми кодировали.
# FMOD-кодер исторически пишет 256/2048 (0x8B), но чужие банки бывают другими,
# поэтому кандидатов проверяем реальным декодером (см. build_ogg_verified).
DEFAULT_BLOCKSIZE = 0x8B
BLOCKSIZE_CANDIDATES = (0x8B, 0x9A, 0xA9, 0x98, 0x89, 0xAA, 0x9B, 0x8A, 0xB8, 0xBB, 0x88, 0x99)


def _ident_header(channels: int, frequency: int, blocksize: int) -> bytes:
    """Идентификационный заголовок Vorbis (30 байт)."""
    return struct.pack("<B6sIBIiiiBB", 1, b"vorbis", 0, max(1, channels),
                       frequency & 0xFFFFFFFF, 0, 0, 0, blocksize, 1)


def vorbis_headers(sample: FsbSample,
                   blocksize: int = DEFAULT_BLOCKSIZE) -> tuple[bytes, bytes, bytes] | None:
    """Три Vorbis-заголовка из FSB5: identification, comment, setup.

    FSB5 хранит только аудиопакеты; identification/setup лежат в чанке
    VORBISDATA (setup — после 8-байтного заголовка id+size). Comment
    восстанавливаем пустой — это стандартный и допустимый вариант.
    """
    setup_blob = sample.vorbis_setup
    if not setup_blob:
        return None
    if len(setup_blob) < 4:
        return None
    # setup_blob = [uint32 packet len?] + packet — в большинстве FSB5 длина уже отрезана
    setup = setup_blob
    if setup[:1] != b"\x05":
        if setup_blob[:1] == b"\x05":
            setup = setup_blob
        else:
            # некоторые паковщики оставляют 4-байтный префикс длины
            cand = setup_blob[4:] if setup_blob[4:5] == b"\x05" else setup_blob
            setup = cand
    if setup[:1] != b"\x05":
        return None
    if (blocksize & 0xF) == 0 or (blocksize >> 4) == 0:
        blocksize = DEFAULT_BLOCKSIZE
    ident = _ident_header(sample.channels, sample.frequency, blocksize)
    vendor = b"salvage-fsb5"
    comment = (b"\x03vorbis" + struct.pack("<I", len(vendor)) + vendor
               + struct.pack("<I", 0) + b"\x01")
    return ident, comment, setup


def build_ogg(sample: FsbSample, payload: bytes,
              blocksize: int = DEFAULT_BLOCKSIZE) -> bytes | None:
    """Собрать валидный Ogg-Vorbis из Vorbis-сэмпла FSB5.

    Возвращает None, если заголовки не восстановимы — вызывающий код обязан
    отдать честный статус, а не «сырой» файл с расширением .ogg.
    """
    headers = vorbis_headers(sample, blocksize)
    if headers is None:
        return None
    ident, comment, setup = headers
    # аудиопакеты: FSB5 v1+ пишет 2-байтную длину перед каждым пакетом
    packets = _split_fsb_vorbis_packets(payload)
    if not packets:
        return None
    # Все аудиопакеты — на одной странице: тогда granule = точное число
    # сэмплов (FMOD уже посчитал его в sample.samples). Дробить на страницы с
    # выдуманными granule нельзя: декодер обрежет поток по последнему granule.
    total = max(0, sample.samples)
    try:
        return ogg.build_stream([ident, comment, setup] + packets,
                                serial=(sample.index * 2654435761 + 0x5A4C) & 0xFFFFFFFF,
                                granules=[total], page_packets=0)
    except ValueError:
        return None


def _probe_decoder():
    """Опциональный декодер для проверки результата (SOX/soundfile/libvorbis)."""
    try:
        import soundfile  # type: ignore
        return soundfile
    except Exception:
        return None


def build_ogg_verified(sample: FsbSample, payload: bytes) -> dict:
    """Собрать Ogg и, если есть декодер, проверить что звук действительно звучит.

    Возвращает {data|None, blocksize, verified, status}:
      * verified=True  — декодер прочитал поток и в нём есть ненулевые сэмплы;
      * verified=False — декодера нет; структура проверена (CRC/серийники/EOS),
                         но звучание не подтверждено (честный статус в отчёте);
      * data=None      — заголовки не восстановимы (вызывающий код пишет .wem
                         и статус «raw», а не подсовывает битый .ogg).
    """
    sf = _probe_decoder()
    best: bytes | None = None
    chosen = DEFAULT_BLOCKSIZE
    for bs in BLOCKSIZE_CANDIDATES:
        data = build_ogg(sample, payload, blocksize=bs)
        if data is None:
            return {"data": None, "blocksize": None, "verified": False,
                    "status": "headers-unrecoverable"}
        if best is None:
            best, chosen = data, bs
        if sf is None:
            break
        try:
            import io
            pcm, _rate = sf.read(io.BytesIO(data), dtype="float32", always_2d=False)
            peak = float(abs(pcm).max()) if len(pcm) else 0.0
        except Exception:
            continue
        if peak > 1e-4:
            return {"data": data, "blocksize": bs, "verified": True, "status": "ok"}
    if sf is None:
        # структура валидна, но звук не проверен: говорим об этом прямо
        return {"data": best, "blocksize": chosen, "verified": False,
                "status": "structural-only"}
    # декодер есть, но все кандидаты дали тишину — честный отказ от .ogg
    return {"data": None, "blocksize": None, "verified": False,
            "status": "decode-silent"}


def _split_fsb_vorbis_packets(payload: bytes) -> list[bytes]:
    """Аудиопакеты FSB5-Vorbis: [uint16 len][vorbis-пакет]..., нулевая длина — конец."""
    out: list[bytes] = []
    p = 0
    n = len(payload)
    while p + 2 <= n:
        size = struct.unpack_from("<H", payload, p)[0]
        p += 2
        if size == 0:
            break
        if p + size > n:
            break
        out.append(payload[p:p + size])
        p += size
    if not out:
        # некоторые банки хранят пакеты без префиксов: тогда отдаём как один пакет
        out = [payload] if payload else []
    return out


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
    """Кодек задаётся полем mode в заголовке (смещение 0x18), накладываем на все сэмплы."""
    try:
        with open(path, "rb") as f:
            head = f.read(0x1C)
        mode = struct.unpack_from("<I", head, 0x18)[0] & 0x1FF
    except (OSError, struct.error):
        return
    for s in fsb.samples:
        s.codec = mode


def sample_payload(fsb: FsbFile, s: FsbSample, data: bytes | None = None) -> bytes:
    if data is None:
        data = fsb.path.read_bytes()
    return data[s.data_offset:s.data_offset + s.data_size]
