"""Full-duplex peer: one TCP connection, a reader thread for incoming voice
messages, and thread-safe sending of outgoing ones (both directions at once)."""
import hashlib
import json
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import protocol as P
from .keys import Identity

DEFAULT_PORT = 12347
CHUNK = 32 * 1024

K_BEGIN, K_CHUNK, K_END, K_TEXT = 0x10, 0x11, 0x12, 0x20


@dataclass
class VoiceMessage:
    msg_id: int
    sample_rate: int
    channels: int
    sample_width: int
    pcm: bytes
    sender: str
    received_at: float = field(default_factory=time.time)

    @property
    def duration(self) -> float:
        frame = self.channels * self.sample_width
        return len(self.pcm) / frame / self.sample_rate if frame and self.sample_rate else 0.0


class Peer:
    def __init__(self, identity: Identity, name: str,
                 on_voice: Callable[[VoiceMessage], None] = lambda m: None,
                 on_text: Callable[[str, str], None] = lambda s, t: None,
                 on_log: Callable[[str], None] = print,
                 on_closed: Callable[[Optional[Exception]], None] = lambda e: None):
        self.identity = identity
        self.name = name
        self.on_voice, self.on_text, self.on_log, self.on_closed = on_voice, on_text, on_log, on_closed
        self.channel: Optional[P.SecureChannel] = None
        self._listener: Optional[socket.socket] = None
        self._next_msg_id = 1
        self._incoming = {}
        self._reader: Optional[threading.Thread] = None

    # ---------- connection setup ----------
    def listen_and_accept(self, port: int = DEFAULT_PORT, host: str = "0.0.0.0",
                          expected_peer_fp: Optional[str] = None, timeout: Optional[float] = None,
                          ready: Optional[threading.Event] = None) -> None:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(1)
        srv.settimeout(timeout)
        self._listener = srv
        self.on_log(f"Listening on {host}:{srv.getsockname()[1]} ...")
        if ready:
            ready.set()
        try:
            conn, addr = srv.accept()
        finally:
            srv.close()          # free the port as soon as the single peer is accepted
            self._listener = None
        conn.settimeout(None)
        self.on_log(f"Connection from {addr[0]}:{addr[1]}")
        self._start(P.handshake_responder(conn, self.identity, self.name, expected_peer_fp))

    def connect(self, host: str, port: int = DEFAULT_PORT,
                expected_peer_fp: Optional[str] = None, timeout: float = 10.0) -> None:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(None)
        self.on_log(f"Connected to {host}:{port}")
        self._start(P.handshake_initiator(sock, self.identity, self.name, expected_peer_fp))

    def _start(self, channel: P.SecureChannel) -> None:
        self.channel = channel
        lk = channel.layer_keys
        self.on_log(f"Secure session with '{channel.peer_name}' (fingerprint {channel.peer_fingerprint})")
        self.on_log(f"  L1 Affine a={lk.affine[0]} b={lk.affine[1]} | "
                    f"L2 Transposition {lk.transposition} | L3 AES-256-GCM")
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    # ---------- sending ----------
    def send_voice(self, pcm: bytes, sample_rate: int, channels: int = 1, sample_width: int = 2) -> int:
        ch = self._require()
        msg_id = self._next_msg_id
        self._next_msg_id += 1
        meta = {"id": msg_id, "rate": sample_rate, "channels": channels, "width": sample_width,
                "size": len(pcm), "sha256": hashlib.sha256(pcm).hexdigest()}
        ch.send(bytes([K_BEGIN]) + json.dumps(meta).encode())
        mid = msg_id.to_bytes(4, "big")
        total = (len(pcm) + CHUNK - 1) // CHUNK
        for n, i in enumerate(range(0, len(pcm), CHUNK), 1):
            ch.send(bytes([K_CHUNK]) + mid + pcm[i:i + CHUNK])
            if n % 20 == 0 and n < total:
                self.on_log(f"  sending… {n}/{total} chunks")
        ch.send(bytes([K_END]) + mid)
        self.on_log(f"Sent voice message #{msg_id}: {len(pcm)} bytes, "
                    f"{(len(pcm) + CHUNK - 1) // CHUNK} encrypted chunks")
        return msg_id

    def send_text(self, text: str) -> None:
        self._require().send(bytes([K_TEXT]) + text.encode())

    def _require(self) -> P.SecureChannel:
        if not self.channel:
            raise RuntimeError("not connected")
        return self.channel

    # ---------- receiving ----------
    def _read_loop(self) -> None:
        err: Optional[Exception] = None
        try:
            while True:
                pt = self.channel.recv()
                if pt is None:
                    self.on_log("Peer closed the session")
                    break
                self._handle(pt)
        except P.SecurityError as e:
            err = e
            self.on_log(f"SECURITY ALERT: {e} -- session terminated")
        except (ConnectionError, OSError) as e:
            err = e
            self.on_log(f"Connection lost: {e}")
        except Exception as e:  # malformed plaintext etc.
            err = e
            self.on_log(f"Protocol error: {e}")
        finally:
            try:
                self.channel.sock.close()
            except OSError:
                pass
            self.on_closed(err)

    def _handle(self, pt: bytes) -> None:
        kind, body = pt[0], pt[1:]
        if kind == K_BEGIN:
            meta = json.loads(body)
            self._incoming[meta["id"]] = (meta, bytearray())
        elif kind == K_CHUNK:
            mid = int.from_bytes(body[:4], "big")
            self._incoming[mid][1].extend(body[4:])
        elif kind == K_END:
            mid = int.from_bytes(body[:4], "big")
            meta, buf = self._incoming.pop(mid)
            pcm = bytes(buf)
            if len(pcm) != meta["size"] or hashlib.sha256(pcm).hexdigest() != meta["sha256"]:
                raise P.SecurityError(f"voice message #{mid} failed end-to-end hash check")
            msg = VoiceMessage(mid, meta["rate"], meta["channels"], meta["width"], pcm,
                               self.channel.peer_name)
            self.on_log(f"Received voice message #{mid}: {msg.duration:.1f}s, SHA-256 verified")
            self.on_voice(msg)
        elif kind == K_TEXT:
            self.on_text(self.channel.peer_name, body.decode(errors="replace"))
        else:
            raise P.ProtocolError(f"unknown message kind {kind}")

    def close(self) -> None:
        if self.channel:
            self.channel.close()
        if self._listener:
            try:
                self._listener.close()
            except OSError:
                pass
