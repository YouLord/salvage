"""Стенд Wwise: `.pck` (AKPK) и `.bnk` (BKHD/DIDX/DATA) с реальными `.wem`.

`.wem` делаем двух видов, чтобы проверять честность статусов:
  * vorbis-wwise — «OggS»-обёртка без `\\x01vorbis` (как в реальных Wwise-версиях);
  * riff — WAV-подобная обёртка (встречается у PCM/XMA-вариантов).

Точные офсеты и размеры пишем в `expected.json` — тесты сверяют байт-в-байт.
"""
from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fixture_base import ensure_dir


def _wem_vorbis(tag: int, n: int = 512) -> bytes:
    body = bytes(((i * 31 + tag) & 0xFF) for i in range(n))
    return b"OggS" + struct.pack("<I", 0) + body


def _wem_riff(tag: int, n: int = 384) -> bytes:
    data = bytes(((i * 17 + tag) & 0xFF) for i in range(n))
    fmt = struct.pack("<HHIIHH", 1, 1, 22050, 44100, 2, 16)
    return (b"RIFF" + struct.pack("<I", 4 + 8 + len(fmt) + 8 + len(data)) + b"WAVE"
            + b"fmt " + struct.pack("<I", len(fmt)) + fmt
            + b"data" + struct.pack("<I", len(data)) + data)


def build(root: Path, *, with_bug: bool = False) -> Path:
    ensure_dir(root)
    wems = {
        1001: _wem_vorbis(1),
        1002: _wem_vorbis(2),
        2001: _wem_riff(3),
    }

    # ---------------- .pck (AKPK, версия 1) ----------------
    # Инвариант старой версии: langs + banks + streams + 0x10 == header_size.
    # Секция streams: [uint32 count][20-байтные записи][данные].
    # Запись: id, block_size(=16), size, offset_в_блоках, language_id.
    entries = [(1001, wems[1001]), (1002, wems[1002])]
    table_size = 4 + 20 * len(entries)
    header_size = 0x18  # физический размер шапки; ниже пересчитаем поле header_size
    table = bytearray(struct.pack("<I", len(entries)))
    body = bytearray()
    cursor = header_size + table_size
    for wem_id, data in entries:
        if cursor % 16:
            pad = 16 - cursor % 16
            body += b"\x00" * pad
            cursor += pad
        table += struct.pack("<IIIII", wem_id, 16, len(data), cursor // 16, 0)
        body += data
        cursor += len(data)
    streams_size = table_size + len(body)
    # поле header_size в старой версии = 0x10 + сумма секций (не физический офсет)
    pck = (b"AKPK" + struct.pack("<IIIII", streams_size + 0x10, 0, 0, 0, streams_size)
           + bytes(table) + bytes(body))
    (root / "Audio.pck").write_bytes(pck)

    # ---------------- .bnk (BKHD + DIDX + DATA) ----------------
    didx_entries = [(2001, wems[2001])]
    didx = b""
    data_blob = bytearray()
    for wem_id, data in didx_entries:
        didx += struct.pack("<III", wem_id, len(data_blob), len(data))
        data_blob += data
    def chunk(tag: bytes, payload: bytes) -> bytes:
        return tag + struct.pack("<I", len(payload)) + payload
    bkhd = struct.pack("<II", 134, 0x0BADBEEF) + struct.pack("<I", 0)  # version, id, language
    bnk = (chunk(b"BKHD", bkhd) + chunk(b"DIDX", didx) + chunk(b"DATA", bytes(data_blob)))
    (root / "SFX.bnk").write_bytes(bnk)

    expected = {
        "pck": {
            "entries": {str(w): {"size": len(d), "sha256": __import__("hashlib").sha256(d).hexdigest()}
                        for w, d in entries},
            "file_size": len(pck),
        },
        "bnk": {
            "entries": {str(w): {"size": len(d), "sha256": __import__("hashlib").sha256(d).hexdigest()}
                        for w, d in didx_entries},
            "version": 134,
        },
        "statuses": {"1001": "vorbis-wwise", "1002": "vorbis-wwise", "2001": "riff"},
    }
    (root / "expected.json").write_text(json.dumps(expected, indent=1), "utf-8")
    return root


BUG_CASE = None


def _inject_bug(root: Path) -> None:
    raise NotImplementedError
