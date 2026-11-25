"""Microphone recording, playback and WAV I/O (16-bit PCM)."""
import threading
import wave
from typing import Optional, Tuple

SAMPLE_RATE = 16000
CHANNELS = 1
SAMPLE_WIDTH = 2  # int16


class Recorder:
    """Start/stop microphone recording; returns raw int16 PCM bytes."""

    def __init__(self, sample_rate: int = SAMPLE_RATE, channels: int = CHANNELS):
        self.sample_rate, self.channels = sample_rate, channels
        self._chunks = []
        self._stream = None
        self._lock = threading.Lock()

    def _cb(self, indata, frames, t, status):
        with self._lock:
            self._chunks.append(bytes(indata))

    def start(self) -> None:
        import sounddevice as sd
        self._chunks = []
        self._stream = sd.RawInputStream(samplerate=self.sample_rate, channels=self.channels,
                                         dtype="int16", callback=self._cb)
        self._stream.start()

    def stop(self) -> bytes:
        if self._stream:
            self._stream.stop()
            self._stream.close()
            self._stream = None
        with self._lock:
            return b"".join(self._chunks)


def play(pcm: bytes, sample_rate: int = SAMPLE_RATE, channels: int = CHANNELS) -> None:
    import numpy as np
    import sounddevice as sd
    arr = np.frombuffer(pcm, dtype=np.int16)
    if channels > 1:
        arr = arr.reshape(-1, channels)
    sd.play(arr, samplerate=sample_rate)


def stop_playback() -> None:
    import sounddevice as sd
    sd.stop()


def save_wav(path: str, pcm: bytes, sample_rate: int = SAMPLE_RATE,
             channels: int = CHANNELS, sample_width: int = SAMPLE_WIDTH) -> None:
    with wave.open(path, "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(sample_width)
        w.setframerate(sample_rate)
        w.writeframes(pcm)


def load_wav(path: str) -> Tuple[bytes, int, int, int]:
    """Returns (pcm, sample_rate, channels, sample_width)."""
    with wave.open(path, "rb") as w:
        return w.readframes(w.getnframes()), w.getframerate(), w.getnchannels(), w.getsampwidth()
