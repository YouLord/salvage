"""Сборка и разбор Ogg-страниц: без зависимостей.

Зачем: FMOD (FSB5) и Wwise хранят Vorbis-поток как набор пакетов без
Ogg-контейнера. Чтобы отдать пользователю файл, который откроется в плеере,
нужно собрать страницы с корректным CRC, serial, granule position и lacing.

Реализация — по RFC 3533 (framing) и granule-правилам Vorbis
(«Vorbis I specification», 4.3.1: granule = номер последнего сэмпла страницы,
первая страница 0, аудиостраницы накапливают сэмплы).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

OGG_MAGIC = b"OggS"

# Таблица CRC-32 Ogg: полином 0x04C11DB7, без отражения, init=0, без xorout.
_CRC_TABLE: list[int] = []


def _build_table() -> list[int]:
    table = []
    for i in range(256):
        r = i << 24
        for _ in range(8):
            r = ((r << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if (r & 0x80000000) else (r << 1) & 0xFFFFFFFF
        table.append(r)
    return table


_CRC_TABLE = _build_table()


def ogg_crc(data: bytes) -> int:
    """CRC-32 страницы (поле crc обнуляется перед расчётом — вызывающий код)."""
    crc = 0
    table = _CRC_TABLE  # локальная ссылка: горячий цикл
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ table[((crc >> 24) & 0xFF) ^ b]
    return crc


@dataclass
class OggPage:
    serial: int
    sequence: int
    granule: int
    header_type: int           # 0x02 начало потока, 0x04 конец, 0x01 продолжение
    segments: list[bytes] = field(default_factory=list)   # пакеты (уже собранные)
    offset: int = 0            # позиция в файле (для разбора)

    @property
    def packets(self) -> list[bytes]:
        return self.segments


def lacing_for(packets: list[bytes]) -> bytes:
    """Lacing-таблица: по 255 на каждый полный блок + остаток (в т.ч. 0 для кратных 255)."""
    out = bytearray()
    for pkt in packets:
        n = len(pkt)
        while n >= 255:
            out.append(255)
            n -= 255
        out.append(n)
    return bytes(out)


def build_page(packets: list[bytes], *, serial: int, sequence: int, granule: int = 0,
               header_type: int = 0) -> bytes:
    """Собрать одну страницу. Каждый элемент packets — самостоятельный пакет."""
    lacing = lacing_for(packets)
    if len(lacing) > 255:
        raise ValueError("слишком много сегментов на страницу (максимум 255)")
    body = b"".join(packets)
    header = struct.pack("<4sBBQIIIB", OGG_MAGIC, 0, header_type,
                         granule & 0xFFFFFFFFFFFFFFFF,
                         serial & 0xFFFFFFFF, sequence, 0, len(lacing)) + lacing
    page = header + body
    crc = ogg_crc(page)
    # перезаписываем crc (смещение 22)
    return page[:22] + struct.pack("<I", crc) + page[26:]


def build_stream(packets: list[bytes], *, serial: int, granules: list[int],
                 page_packets: int = 0) -> bytes:
    """Собрать Ogg-поток из трёх Vorbis-заголовков и аудиопакетов.

    packets[0..2] — идентификация, комментарий, setup; дальше — аудио.
    page_packets — сколько аудиопакетов класть на страницу (0 — все в одну).

    granule: промежуточные страницы получают -1 (0xFFFF...), это легально
    по спецификации Ogg; итоговый granule (суммарные сэмплы) выставляется
    только на последней странице. Прямое следствие: точный seek по времени
    приблизительный — плеер ищет по страницам, а не по сэмплам.
    """
    if len(packets) < 3:
        raise ValueError("нужно минимум 3 заголовочных пакета Vorbis")
    out = bytearray()
    serial &= 0xFFFFFFFF
    out += build_page([packets[0]], serial=serial, sequence=0, granule=0, header_type=0x02)
    out += build_page([packets[1], packets[2]], serial=serial, sequence=1,
                      granule=0, header_type=0)
    seq = 2
    audio = packets[3:]
    final_granule = granules[-1] if granules else 0
    if not audio:
        out += build_page([b""], serial=serial, sequence=seq,
                          granule=final_granule, header_type=0x04)
        return bytes(out)
    step = page_packets if page_packets > 0 else len(audio)
    for start in range(0, len(audio), step):
        chunk = audio[start:start + step]
        last = start + step >= len(audio)
        out += build_page(chunk, serial=serial, sequence=seq,
                          granule=final_granule if last else -1,
                          header_type=0x04 if last else 0)
        seq += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# Разбор (для тестов и для честной проверки чужих Ogg)
# ---------------------------------------------------------------------------

class OggError(ValueError):
    pass


def parse_pages(data: bytes) -> list[OggPage]:
    """Разобрать Ogg-файл в страницы (с проверкой CRC)."""
    pages: list[OggPage] = []
    pos = 0
    while pos < len(data):
        if data[pos:pos + 4] != OGG_MAGIC:
            raise OggError(f"нет OggS на смещении {pos}")
        if pos + 27 > len(data):
            raise OggError("обрезанный заголовок страницы")
        _ver, htype, gran, serial, seq, crc, nseg = struct.unpack_from("<BBqIIIB", data, pos + 4)
        lacing = data[pos + 27:pos + 27 + nseg]
        body_len = sum(lacing)
        total = 27 + nseg + body_len
        if pos + total > len(data):
            raise OggError(f"обрезанная страница на {pos}")
        raw = bytearray(data[pos:pos + total])
        stored = struct.unpack_from("<I", raw, 22)[0]
        raw[22:26] = b"\x00\x00\x00\x00"
        if ogg_crc(bytes(raw)) != stored:
            raise OggError(f"CRC не сходится на странице {pos}")
        # нарезка тела по lacing
        packets: list[bytes] = []
        cur = bytearray()
        off = pos + 27 + nseg
        for lv in lacing:
            cur += data[off:off + lv]
            off += lv
            if lv < 255:
                packets.append(bytes(cur))
                cur = bytearray()
        if cur:  # продолжение пакета на следующей странице (в наших файлах не встречается)
            packets.append(bytes(cur))
        pages.append(OggPage(serial=serial, sequence=seq, granule=gran,
                             header_type=htype, segments=packets, offset=pos))
        pos += total
    return pages


def verify_stream(data: bytes) -> dict:
    """Проверить, что это валидный Ogg-Vorbis: страницы, CRC, serial, порядок, EOS."""
    pages = parse_pages(data)
    if not pages:
        raise OggError("пустой поток")
    serial = pages[0].serial
    for i, p in enumerate(pages):
        if p.serial != serial:
            raise OggError(f"сменился serial на странице {i}")
        if p.sequence != i:
            raise OggError(f"нарушен порядок страниц: {p.sequence} != {i}")
    if not (pages[0].header_type & 0x02):
        raise OggError("первая страница без BOS-флага")
    if not (pages[-1].header_type & 0x04):
        raise OggError("последняя страница без EOS-флага")
    head = pages[0].segments[0] if pages[0].segments else b""
    if not (head[:1] == b"\x01" and head[1:7] == b"vorbis"):
        raise OggError("нет идентификационного заголовка Vorbis")
    # granule промежуточных страниц обязан быть -1 (или монотонно расти);
    # последняя — итоговая сумма сэмплов, и она не меньше всех предыдущих.
    seen: list[int] = []
    for i, p in enumerate(pages):
        if p.granule == -1:
            continue
        if seen and p.granule < seen[-1]:
            raise OggError(f"granule убывает на странице {i}: {p.granule} < {seen[-1]}")
        seen.append(p.granule)
    return {
        "pages": len(pages),
        "serial": serial,
        "granule": pages[-1].granule,
        "headers": sum(1 for p in pages[:2] for _ in p.segments),
        "granules": [p.granule for p in pages],
    }
