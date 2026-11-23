"""Сборка входного ассета tests/assets/tone.ogg (реальный Vorbis, коммитится).

Фикстуры (tests/fixtures/) в .gitignore, а входной ассет — нет: он нужен
тестам, которые доказывают «получившийся Ogg открывается в плеерах».

Запуск (нужен пакет soundfile/libvorbis): python tests/make_asset_tone.py
"""
from __future__ import annotations

import math
import struct
import sys
from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "assets"
RATE = 22050
SECONDS = 0.6
AMPLITUDE = 0.35


def tone_pcm() -> bytes:
    """Две ноты (440 и 660 Гц) + затухание — не «прямая линия», чтобы декодер не соврал."""
    n = int(RATE * SECONDS)
    frames = bytearray()
    for i in range(n):
        t = i / RATE
        freq = 440.0 if i < n // 2 else 660.0
        env = 1.0 - i / n                      # плавное затухание
        # лёгкая вторая гармоника — декодеру есть что восстанавливать
        value = AMPLITUDE * env * (math.sin(2 * math.pi * freq * t)
                                   + 0.3 * math.sin(4 * math.pi * freq * t))
        sample = max(-1.0, min(1.0, value))
        frames += struct.pack("<h", int(sample * 32767))
    return bytes(frames)


def build(target: Path | None = None) -> Path:
    import numpy as np
    import soundfile as sf

    ASSETS.mkdir(parents=True, exist_ok=True)
    target = target or (ASSETS / "tone.ogg")
    raw = tone_pcm()
    samples = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    sf.write(str(target), samples, RATE, format="OGG", subtype="VORBIS")
    return target


def build_wav(target: Path) -> Path:
    """PCM-эталон рядом (в fixtures, не коммитится): с чем сверять декодирование."""
    import wave
    target.parent.mkdir(parents=True, exist_ok=True)
    with wave.open(str(target), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(RATE)
        w.writeframes(tone_pcm())
    return target


if __name__ == "__main__":
    if "soundfile" not in sys.modules:
        try:
            import soundfile  # noqa: F401
        except ImportError:
            raise SystemExit("нужен soundfile: pip install soundfile")
    path = build()
    print(f"собран {path} ({path.stat().st_size} Б)")
