"""Inspection relay for the middle laptop.

The source is configured to connect to this relay (explicitly), and the relay
forwards every frame to the destination and back. It is used to evaluate the
system from the middle position:

* Passive observation: every frame is logged (type, size, Shannon entropy)
  and the captured DATA ciphertext is saved for offline analysis.
* Integrity test modes (to verify the defenses work):
    - "tamper": flip one bit inside one DATA frame  -> receiver must reject (GCM tag)
    - "replay": re-send an earlier DATA frame       -> receiver must reject (sequence check)
    - "drop":   silently drop one DATA frame        -> receiver must detect the gap / hash mismatch
"""
import math
import os
import socket
import threading
import time
from collections import Counter
from typing import Callable, Optional

from . import protocol as P

MODES = ("observe", "tamper", "replay", "drop")
TYPE_NAMES = {P.T_HELLO: "HELLO", P.T_KEYX: "KEYX", P.T_DATA: "DATA", P.T_BYE: "BYE"}
BURST_GAP = 1.0   # seconds of silence on a direction that start a new intercepted message


class Intercepted:
    """Ciphertext captured from one burst of DATA frames (one voice message)."""

    def __init__(self, direction: str):
        self.direction = direction
        self.started = time.time()
        self.last = self.started
        self.data = bytearray()
        self.frames = 0

    def as_pcm(self) -> bytes:
        """Interpret the ciphertext bytes as 16-bit PCM, scaled to 1/4 volume
        (random bytes at full scale are uncomfortably loud)."""
        import numpy as np
        raw = bytes(self.data[: len(self.data) // 2 * 2])
        arr = (np.frombuffer(raw, dtype="<i2") // 4).astype("<i2")
        return arr.tobytes()

    def seconds(self, rate: int = 16000) -> float:
        return len(self.data) / 2 / rate

    def label(self) -> str:
        return (f"{time.strftime('%H:%M:%S', time.localtime(self.started))}  {self.direction}  "
                f"{self.frames} frames, {len(self.data)} B ≈ {self.seconds():.1f}s, "
                f"entropy {shannon_entropy(bytes(self.data[:200000])):.3f}")


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


class InspectionRelay:
    def __init__(self, listen_port: int, dest_host: str, dest_port: int,
                 mode: str = "observe", trigger_frame: int = 5,
                 capture_dir: Optional[str] = "captures",
                 on_log: Callable[[str], None] = print):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.listen_port, self.dest = listen_port, (dest_host, dest_port)
        self.mode, self.trigger_frame = mode, trigger_frame
        self.capture_dir, self.on_log = capture_dir, on_log
        self.stats = {"frames": 0, "bytes": 0, "data_frames": 0}
        self._srv: Optional[socket.socket] = None
        self._capture = None
        self._lock = threading.Lock()
        self.done = threading.Event()
        self.intercepted = []            # list[Intercepted], newest last
        self._current = {}               # direction -> Intercepted

    def _record(self, direction: str, ct: bytes) -> None:
        now = time.time()
        with self._lock:
            cur = self._current.get(direction)
            if cur is None or now - cur.last > BURST_GAP:
                cur = Intercepted(direction)
                self._current[direction] = cur
                self.intercepted.append(cur)
            cur.data += ct
            cur.frames += 1
            cur.last = now

    def save_intercepted_wavs(self) -> None:
        if not self.capture_dir:
            return
        from .audio import save_wav
        for i, m in enumerate(self.intercepted, 1):
            path = os.path.join(self.capture_dir, time.strftime(
                f"intercepted_%H%M%S_{i}.wav", time.localtime(m.started)))
            save_wav(path, m.as_pcm())
            self.on_log(f"[relay] saved what the middle laptop hears: {path}")

    def serve_once(self, ready: Optional[threading.Event] = None) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", self.listen_port))
        srv.listen(1)
        self._srv = srv
        self.listen_port = srv.getsockname()[1]
        self.on_log(f"[relay] listening on :{self.listen_port}, forwarding to "
                    f"{self.dest[0]}:{self.dest[1]} (mode={self.mode})")
        if ready:
            ready.set()
        a, addr = srv.accept()
        self.on_log(f"[relay] source connected from {addr[0]}")
        b = socket.create_connection(self.dest)
        self.on_log("[relay] connected to destination")
        if self.capture_dir:
            os.makedirs(self.capture_dir, exist_ok=True)
            path = os.path.join(self.capture_dir, time.strftime("capture_%Y%m%d_%H%M%S.bin"))
            self._capture = open(path, "wb")
            self.on_log(f"[relay] saving captured ciphertext to {path}")
        t1 = threading.Thread(target=self._pump, args=(a, b, "A->B", True), daemon=True)
        t2 = threading.Thread(target=self._pump, args=(b, a, "B->A", False), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
        if self._capture:
            self._capture.close()
        srv.close()
        self.save_intercepted_wavs()
        self.on_log(f"[relay] finished: {self.stats}")
        self.done.set()

    def _pump(self, src: socket.socket, dst: socket.socket, label: str, apply_mode: bool) -> None:
        buf = bytearray()
        data_count = 0
        history = []
        try:
            while True:
                chunk = src.recv(65536)
                if not chunk:
                    break
                buf += chunk
                for ftype, payload, raw in P.parse_frames(buf):
                    out = [raw]
                    with self._lock:
                        self.stats["frames"] += 1
                        self.stats["bytes"] += len(raw)
                    name = TYPE_NAMES.get(ftype, str(ftype))
                    if ftype == P.T_DATA:
                        data_count += 1
                        with self._lock:
                            self.stats["data_frames"] += 1
                        ct = payload[8:]
                        if self._capture:
                            self._capture.write(ct)
                        self._record(label, ct)
                        if data_count <= 3 or data_count % 20 == 0:
                            self.on_log(f"[relay] {label} DATA seq={int.from_bytes(payload[:8], 'big')} "
                                        f"{len(ct)}B entropy={shannon_entropy(ct):.3f} bits/byte")
                        if apply_mode and data_count == self.trigger_frame:
                            out = self._apply(raw, history)
                        history.append(raw)
                    else:
                        self.on_log(f"[relay] {label} {name} ({len(payload)}B)")
                    for r in out:
                        dst.sendall(r)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _apply(self, raw: bytes, history):
        if self.mode == "tamper":
            mod = bytearray(raw)
            mod[-20] ^= 0x01          # flip one bit in the ciphertext body
            self.on_log(f"[relay] TEST: flipped 1 bit in DATA frame #{self.trigger_frame}")
            return [bytes(mod)]
        if self.mode == "replay" and history:
            self.on_log(f"[relay] TEST: re-sending an earlier DATA frame before #{self.trigger_frame}")
            return [raw, history[0]]
        if self.mode == "drop":
            self.on_log(f"[relay] TEST: dropped DATA frame #{self.trigger_frame}")
            return []
        return [raw]

    def stop(self) -> None:
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass
