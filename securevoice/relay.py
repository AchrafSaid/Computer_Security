"""Inspection relay for the middle laptop (the man in the middle).

The source connects to this relay explicitly; the relay forwards every frame to
the destination and back, and can act on the traffic from the middle position.

Passive modes
* "observe": log every frame (type, size, Shannon entropy) and save the captured
  DATA ciphertext. Without the key this is only noise.
* "crack":   observe, then brute-force the shared PIN from the captured handshake,
  recover the AES key, and DECRYPT the intercepted voice -- the attacker hears the
  real message. Neither side can tell, because a passive tap changes nothing.

Active modes (modify the stream from the middle)
* "tamper" / "replay" / "drop": corrupt / re-send / drop one DATA frame. With a
  strong key these have no key, so the destination's AES-GCM / sequence checks
  REJECT the message -- this demonstrates the defence working.
* "forge":  brute-force the PIN, then DROP the source's real message and send the
  destination a DIFFERENT (fake) voice message, encrypted with the recovered key.
  Because the attacker holds the key, the forged frames pass every check, so the
  destination plays the fake message and neither side notices.

The active break ("forge") works only because the key was a short PIN that brute
force could guess. A strong passphrase cannot be guessed, the attacker never gets
the key, and tamper/replay/drop are caught -- that is the whole lesson.
"""
import json
import math
import os
import socket
import threading
import time
from collections import Counter
from typing import Callable, List, Optional

from . import analysis
from . import keys as K
from . import protocol as P

MODES = ("observe", "crack", "tamper", "replay", "drop", "forge")
ACTIVE_MODES = ("tamper", "replay", "drop", "forge")
TYPE_NAMES = {P.T_HELLO: "HELLO", P.T_AUTH: "AUTH", P.T_DATA: "DATA", P.T_BYE: "BYE"}
BURST_GAP = 1.0   # seconds of silence on a direction that start a new intercepted message

# which AES direction byte each relay pump carries
DIR_OF = {"A->B": P.DIR_INITIATOR, "B->A": P.DIR_RESPONDER}


class Intercepted:
    """Ciphertext captured from one burst of DATA frames (one voice message)."""

    def __init__(self, direction: str):
        self.direction = direction
        self.direction_byte = DIR_OF.get(direction, P.DIR_INITIATOR)
        self.started = time.time()
        self.last = self.started
        self.data = bytearray()
        self.frames = 0
        self.frames_data = []            # list[(seq, ciphertext)] for decryption

    def as_pcm(self) -> bytes:
        """Interpret the ciphertext bytes as 16-bit PCM, scaled to 1/4 volume
        (random bytes at full scale are uncomfortably loud)."""
        import numpy as np
        raw = bytes(self.data[: len(self.data) // 2 * 2])
        arr = (np.frombuffer(raw, dtype="<i2") // 4).astype("<i2")
        return arr.tobytes()

    def decrypt(self, aes_key: bytes) -> "tuple[bytes, Optional[dict]]":
        """Decrypt every captured frame with the recovered key and reassemble the
        original PCM (what the victim actually sent). Returns (pcm, meta)."""
        from .crypto_layers import AESLayer
        from .peer import K_BEGIN, K_CHUNK, K_END
        aes = AESLayer(aes_key)
        pcm = bytearray()
        meta: Optional[dict] = None
        for seq, ct in self.frames_data:
            pt = aes.decrypt(ct, P.data_nonce(self.direction_byte, seq),
                             P.data_aad(self.direction_byte, seq))
            kind, body = pt[0], pt[1:]
            if kind == K_BEGIN:
                meta = json.loads(body)
            elif kind == K_CHUNK:
                pcm += body[4:]
            elif kind == K_END:
                pass
        return bytes(pcm), meta

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
                 on_log: Callable[[str], None] = print,
                 fake_pcm: Optional[bytes] = None, fake_rate: int = 16000,
                 pin_digits: int = 4, iterations: Optional[int] = None):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.listen_port, self.dest = listen_port, (dest_host, dest_port)
        self.mode, self.trigger_frame = mode, trigger_frame
        self.capture_dir, self.on_log = capture_dir, on_log
        self.fake_pcm, self.fake_rate = fake_pcm, fake_rate
        self.pin_digits = pin_digits
        self.iterations = K.PBKDF2_ITERATIONS if iterations is None else iterations
        self.stats = {"frames": 0, "bytes": 0, "data_frames": 0}
        self._srv: Optional[socket.socket] = None
        self._capture = None
        self._lock = threading.Lock()
        self.done = threading.Event()
        self.intercepted = []            # list[Intercepted], newest last
        self._current = {}               # direction -> Intercepted
        # man-in-the-middle state
        self._hs = {}                    # captured handshake fields
        self._cracked = False
        self._crack_failed = False
        self._forged = False
        self.cracked_pin: Optional[str] = None
        self.aes_key: Optional[bytes] = None
        self.recovered = []              # list[(Intercepted, pcm, rate)] after a crack

    # ---------------- capture ----------------
    def _record(self, direction: str, seq: int, ct: bytes) -> None:
        now = time.time()
        with self._lock:
            cur = self._current.get(direction)
            if cur is None or now - cur.last > BURST_GAP:
                cur = Intercepted(direction)
                self._current[direction] = cur
                self.intercepted.append(cur)
            cur.data += ct
            cur.frames += 1
            cur.frames_data.append((seq, ct))
            cur.last = now

    def _capture_handshake(self, direction: str, ftype: int, payload: bytes) -> None:
        if ftype != P.T_HELLO:
            return
        try:
            d = json.loads(payload)
        except ValueError:
            return
        with self._lock:
            if direction == "A->B":                    # initiator's HELLO
                self._hs["name_i"] = d.get("name", "")
                self._hs["nonce_i"] = bytes.fromhex(d.get("nonce", ""))
            else:                                       # responder's HELLO (+ proof)
                self._hs["name_r"] = d.get("name", "")
                self._hs["nonce_r"] = bytes.fromhex(d.get("nonce", ""))
                if "proof" in d:
                    self._hs["proof_r"] = bytes.fromhex(d["proof"])

    def _handshake_ready(self) -> bool:
        return all(k in self._hs for k in
                   ("name_i", "nonce_i", "name_r", "nonce_r", "proof_r"))

    # ---------------- the man-in-the-middle break ----------------
    def _ensure_cracked(self) -> Optional[bytes]:
        """Brute-force the PIN from the captured handshake (once). Returns the AES key."""
        if self._cracked:
            return self.aes_key
        if self._crack_failed or not self._handshake_ready():
            return None
        h = dict(self._hs)
        self.on_log(f"[relay] captured the handshake; brute-forcing the "
                    f"{self.pin_digits}-digit PIN ({10 ** self.pin_digits:,} keys)…")
        r = analysis.brute_force_passphrase(
            h["name_i"], h["name_r"], h["nonce_i"], h["nonce_r"], h["proof_r"],
            role=b"R", iterations=self.iterations,
            candidates=analysis.pin_candidates(self.pin_digits))
        if not r["success"]:
            self._crack_failed = True
            self.on_log(f"[relay] brute force gave up after {r['tries']:,} guesses in "
                        f"{r['secs']:.1f}s — the passphrase is not a short PIN (safe).")
            return None
        self._cracked = True
        self.cracked_pin, self.aes_key = r["passphrase"], r["aes_key"]
        self.on_log(f"[relay] *** CRACKED the PIN by brute force: '{r['passphrase']}' "
                    f"({r['tries']:,} guesses, {r['secs']:.1f}s) — AES-256 key recovered ***")
        return self.aes_key

    def _send_forged_message(self, dst: socket.socket) -> None:
        """Encrypt the attacker's fake PCM with the recovered key and send it to the
        destination as DIR_INITIATOR, seq 0.., so it looks like the real source."""
        from .peer import K_BEGIN, K_CHUNK, K_END, CHUNK
        from .crypto_layers import AESLayer
        import hashlib
        key = self._ensure_cracked()
        if not key or not self.fake_pcm:
            return
        aes = AESLayer(key)
        seq = 0

        def emit(pt: bytes):
            nonlocal seq
            ct = aes.encrypt(pt, P.data_nonce(P.DIR_INITIATOR, seq),
                             P.data_aad(P.DIR_INITIATOR, seq))
            P.send_frame(dst, P.T_DATA, seq.to_bytes(8, "big") + ct)
            seq += 1

        pcm = self.fake_pcm
        meta = {"id": 1, "rate": self.fake_rate, "channels": 1, "width": 2,
                "size": len(pcm), "sha256": hashlib.sha256(pcm).hexdigest()}
        emit(bytes([K_BEGIN]) + json.dumps(meta).encode())
        mid = (1).to_bytes(4, "big")
        for i in range(0, len(pcm), CHUNK):
            emit(bytes([K_CHUNK]) + mid + pcm[i:i + CHUNK])
        emit(bytes([K_END]) + mid)
        self.on_log(f"[relay] *** FORGED a fake voice message ({len(pcm)} bytes, "
                    f"{seq} frames) and sent it to the destination as the real source ***")

    def _crack_and_recover(self) -> None:
        """After serving (crack mode): brute-force the PIN and decrypt every
        intercepted voice message into the real audio the victim sent."""
        key = self._ensure_cracked()
        if not key:
            return
        from .audio import save_wav
        if self.capture_dir:
            os.makedirs(self.capture_dir, exist_ok=True)
        for i, m in enumerate(self.intercepted, 1):
            try:
                pcm, meta = m.decrypt(key)
            except Exception as e:                       # noqa: BLE001 (report and continue)
                self.on_log(f"[relay] could not decrypt message {i}: {e}")
                continue
            if not pcm:
                continue
            rate = int(meta.get("rate", 16000)) if meta else 16000
            self.recovered.append((m, pcm, rate))
            if self.capture_dir:
                path = os.path.join(self.capture_dir, time.strftime(
                    f"recovered_%H%M%S_{i}.wav", time.localtime(m.started)))
                save_wav(path, pcm, rate)
                self.on_log(f"[relay] decrypted the REAL voice the victim sent → {path} "
                            f"({len(pcm)} bytes, {len(pcm) / 2 / rate:.1f}s)")

    def save_intercepted_wavs(self) -> None:
        if not self.capture_dir:
            return
        from .audio import save_wav
        for i, m in enumerate(self.intercepted, 1):
            path = os.path.join(self.capture_dir, time.strftime(
                f"intercepted_%H%M%S_{i}.wav", time.localtime(m.started)))
            save_wav(path, m.as_pcm())
            self.on_log(f"[relay] saved what the middle laptop hears (noise): {path}")

    # ---------------- serving ----------------
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
        if self.mode in ("crack", "forge"):
            self._crack_and_recover()      # also lets the attacker hear the real message
        self.on_log(f"[relay] finished: {self.stats}")
        self.done.set()

    def _pump(self, src: socket.socket, dst: socket.socket, label: str, apply_mode: bool) -> None:
        buf = bytearray()
        data_count = 0
        history = []
        forging = apply_mode and self.mode == "forge"
        if forging and not self.fake_pcm:
            self.on_log("[relay] forge mode needs a fake recording; forwarding unchanged instead")
            forging = False
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
                        seq = int.from_bytes(payload[:8], "big")
                        ct = payload[8:]
                        if self._capture:
                            self._capture.write(ct)
                        self._record(label, seq, ct)
                        if data_count <= 3 or data_count % 20 == 0:
                            self.on_log(f"[relay] {label} DATA seq={seq} {len(ct)}B "
                                        f"entropy={shannon_entropy(ct):.3f} bits/byte")
                        if forging:
                            # drop the real message; on the first frame, inject the fake one
                            out = []
                            if not self._forged:
                                self._forged = True
                                self._send_forged_message(dst)
                        elif apply_mode and data_count == self.trigger_frame:
                            out = self._apply(raw, history)
                        history.append(raw)
                    else:
                        self._capture_handshake(label, ftype, payload)
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
