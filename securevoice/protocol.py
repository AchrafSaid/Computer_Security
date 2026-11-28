"""Wire protocol: length-prefixed frames, authenticated handshake and the
secure channel that applies the three-layer cipher to every frame.

Frame   = len(4, big-endian, covers type+payload) | type(1) | payload
HELLO   = JSON {name, nonce}                 initiator -> responder  (plaintext)
HELLO   = JSON {name, nonce, proof}          responder -> initiator
AUTH    = JSON {proof}                       initiator -> responder
DATA    = seq(8) | ciphertext                (after handshake)
BYE     = empty

Security properties
- Keys come from a pre-shared passphrase (see keys.py). Both sides contribute a
  fresh random nonce, so every session has new layer keys.
- Mutual authentication: each side sends HMAC-SHA256(auth key, role | transcript).
  Without the passphrase a man in the middle cannot compute a valid proof, and
  the initiator only sends its proof after the responder's proof checked out.
- DATA frames: AES-GCM tag covers the ciphertext and the AAD (type|dir|seq);
  receivers require strictly increasing sequence numbers, so modified,
  reordered or replayed frames are rejected.
"""
import hashlib
import json
import os
import socket
import struct
import threading
from typing import Optional, Tuple

from cryptography.exceptions import InvalidTag

from . import keys as K

T_HELLO, T_AUTH, T_DATA, T_BYE = 1, 2, 3, 4
MAX_FRAME = 4 * 1024 * 1024
DIR_INITIATOR, DIR_RESPONDER = 0x01, 0x02


class ProtocolError(Exception):
    pass


class SecurityError(ProtocolError):
    """Raised when an integrity / authenticity check fails."""


# ---------------- framing ----------------
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


def send_frame(sock: socket.socket, ftype: int, payload: bytes) -> None:
    sock.sendall(struct.pack(">IB", len(payload) + 1, ftype) + payload)


def recv_frame(sock: socket.socket) -> Tuple[int, bytes]:
    (length,) = struct.unpack(">I", _recv_exact(sock, 4))
    if length < 1 or length > MAX_FRAME:
        raise ProtocolError(f"bad frame length {length}")
    body = _recv_exact(sock, length)
    return body[0], body[1:]


def parse_frames(buffer: bytearray):
    """Incrementally parse frames from a byte buffer (used by the relay).
    Yields (type, payload, raw_bytes) and removes them from the buffer."""
    while len(buffer) >= 4:
        (length,) = struct.unpack(">I", buffer[:4])
        if length < 1 or length > MAX_FRAME or len(buffer) < 4 + length:
            return
        raw = bytes(buffer[:4 + length])
        del buffer[:4 + length]
        yield raw[4], raw[5:], raw


# ---------------- secure channel ----------------
class SecureChannel:
    def __init__(self, sock: socket.socket, cipher, send_dir: int, recv_dir: int,
                 peer_name: str, layer_keys: K.LayerKeys):
        self.sock = sock
        self.cipher = cipher
        self.send_dir = send_dir
        self.recv_dir = recv_dir
        self.peer_name = peer_name
        self.layer_keys = layer_keys
        self._send_seq = 0
        self._last_recv_seq = -1
        self._send_lock = threading.Lock()

    @staticmethod
    def _nonce(direction: int, seq: int) -> bytes:
        return bytes([direction, 0, 0, 0]) + seq.to_bytes(8, "big")

    @staticmethod
    def _aad(direction: int, seq: int) -> bytes:
        return bytes([T_DATA, direction]) + seq.to_bytes(8, "big")

    def send(self, plaintext: bytes) -> None:
        with self._send_lock:
            seq = self._send_seq
            self._send_seq += 1
            ct = self.cipher.encrypt(plaintext, self._nonce(self.send_dir, seq),
                                     self._aad(self.send_dir, seq))
            send_frame(self.sock, T_DATA, seq.to_bytes(8, "big") + ct)

    def recv(self) -> Optional[bytes]:
        """Returns decrypted plaintext, or None when the peer said BYE."""
        ftype, payload = recv_frame(self.sock)
        if ftype == T_BYE:
            return None
        if ftype != T_DATA or len(payload) < 8:
            raise ProtocolError(f"unexpected frame type {ftype}")
        seq = int.from_bytes(payload[:8], "big")
        if seq <= self._last_recv_seq:
            raise SecurityError(f"replayed/reordered frame (seq {seq} <= {self._last_recv_seq})")
        if seq != self._last_recv_seq + 1:
            raise SecurityError(f"missing frame(s): expected seq {self._last_recv_seq + 1}, got {seq}")
        try:
            pt = self.cipher.decrypt(payload[8:], self._nonce(self.recv_dir, seq),
                                     self._aad(self.recv_dir, seq))
        except InvalidTag:
            raise SecurityError(f"integrity check failed on frame seq {seq} (modified data)")
        self._last_recv_seq = seq
        return pt

    def close(self) -> None:
        try:
            with self._send_lock:
                send_frame(self.sock, T_BYE, b"")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------- handshake ----------------
WRONG_PASSPHRASE = ("authentication failed: the other side does not know the same "
                    "passphrase (wrong passphrase, or someone in the middle)")


def _transcript(name_i: str, name_r: str, nonce_i: bytes, nonce_r: bytes) -> bytes:
    h = hashlib.sha256(b"SECUREVOICE-PSK-v2")
    for part in (name_i.encode(), name_r.encode(), nonce_i, nonce_r):
        h.update(len(part).to_bytes(4, "big") + part)
    return h.digest()


def _read_json(sock, expected_type: int, what: str) -> dict:
    ftype, payload = recv_frame(sock)
    if ftype != expected_type:
        raise ProtocolError(f"expected {what}")
    try:
        return json.loads(payload)
    except ValueError:
        raise ProtocolError(f"malformed {what}")


def _session(passphrase: str, name_i: str, name_r: str, nonce_i: bytes, nonce_r: bytes):
    master = K.session_master(passphrase, nonce_i + nonce_r)
    transcript = _transcript(name_i, name_r, nonce_i, nonce_r)
    return K.auth_key(master), transcript, K.derive_layer_keys(master, transcript)


def handshake_initiator(sock, passphrase: str, name: str) -> SecureChannel:
    nonce_i = os.urandom(K.NONCE_LEN)
    send_frame(sock, T_HELLO, json.dumps({"name": name, "nonce": nonce_i.hex()}).encode())
    data = _read_json(sock, T_HELLO, "HELLO")
    peer_name, nonce_r = data["name"], bytes.fromhex(data["nonce"])
    akey, transcript, lk = _session(passphrase, name, peer_name, nonce_i, nonce_r)
    if not K.check_proof(akey, b"R", transcript, bytes.fromhex(data.get("proof", ""))):
        raise SecurityError(WRONG_PASSPHRASE)
    send_frame(sock, T_AUTH, json.dumps({"proof": K.proof(akey, b"I", transcript).hex()}).encode())
    return SecureChannel(sock, K.build_cipher(lk), DIR_INITIATOR, DIR_RESPONDER, peer_name, lk)


def handshake_responder(sock, passphrase: str, name: str) -> SecureChannel:
    data = _read_json(sock, T_HELLO, "HELLO")
    peer_name, nonce_i = data["name"], bytes.fromhex(data["nonce"])
    nonce_r = os.urandom(K.NONCE_LEN)
    akey, transcript, lk = _session(passphrase, peer_name, name, nonce_i, nonce_r)
    send_frame(sock, T_HELLO, json.dumps({"name": name, "nonce": nonce_r.hex(),
                                          "proof": K.proof(akey, b"R", transcript).hex()}).encode())
    try:
        data = _read_json(sock, T_AUTH, "AUTH")
    except ConnectionError:            # the initiator rejected our proof and hung up
        raise SecurityError(WRONG_PASSPHRASE)
    if not K.check_proof(akey, b"I", transcript, bytes.fromhex(data.get("proof", ""))):
        raise SecurityError(WRONG_PASSPHRASE)
    return SecureChannel(sock, K.build_cipher(lk), DIR_RESPONDER, DIR_INITIATOR, peer_name, lk)
