"""Wire protocol: length-prefixed frames, authenticated handshake and the
secure channel that applies the three-layer cipher to every frame.

Frame   = len(4, big-endian, covers type+payload) | type(1) | payload
HELLO   = JSON {name, pub (PEM), nonce (hex)}              (plaintext)
KEYX    = JSON {wrapped (hex), sig (hex)}                  (initiator -> responder)
DATA    = seq(8) | ciphertext                              (after handshake)
BYE     = empty

Security properties
- Session secret is wrapped with the responder's RSA public key (OAEP) and
  signed by the initiator (PSS) together with both hello nonces, so it is
  fresh and bound to both identities.
- Each side may pin the peer's public-key fingerprint (exchanged out of band);
  a mismatch aborts the handshake.
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

from cryptography.exceptions import InvalidSignature, InvalidTag

from . import keys as K

T_HELLO, T_KEYX, T_DATA, T_BYE = 1, 2, 3, 4
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
                 peer_name: str, peer_fingerprint: str, layer_keys: K.LayerKeys):
        self.sock = sock
        self.cipher = cipher
        self.send_dir = send_dir
        self.recv_dir = recv_dir
        self.peer_name = peer_name
        self.peer_fingerprint = peer_fingerprint
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
def _hello(identity: K.Identity, name: str) -> Tuple[bytes, bytes]:
    nonce = os.urandom(16)
    msg = json.dumps({"name": name, "pub": identity.public_pem().decode(),
                      "nonce": nonce.hex()}).encode()
    return msg, nonce


def _read_hello(sock, expected_fp: Optional[str]):
    ftype, payload = recv_frame(sock)
    if ftype != T_HELLO:
        raise ProtocolError("expected HELLO")
    data = json.loads(payload)
    pem = data["pub"].encode()
    pub = K.load_public(pem)
    fp = K.fingerprint(pem)
    if expected_fp and _norm(expected_fp) != _norm(fp):
        raise SecurityError(f"peer fingerprint {fp} does not match the pinned value")
    return data["name"], pub, pem, bytes.fromhex(data["nonce"]), fp


def _norm(fp: str) -> str:
    return fp.replace(":", "").replace(" ", "").upper()


def _transcript(wrapped: bytes, init_pem: bytes, resp_pem: bytes,
                init_nonce: bytes, resp_nonce: bytes) -> bytes:
    return (b"SECUREVOICE-KEYX" + hashlib.sha256(init_pem).digest()
            + hashlib.sha256(resp_pem).digest() + init_nonce + resp_nonce + wrapped)


def handshake_initiator(sock, identity: K.Identity, name: str,
                        expected_peer_fp: Optional[str] = None) -> SecureChannel:
    hello, my_nonce = _hello(identity, name)
    send_frame(sock, T_HELLO, hello)
    peer_name, peer_pub, peer_pem, peer_nonce, peer_fp = _read_hello(sock, expected_peer_fp)

    secret = os.urandom(K.SESSION_SECRET_LEN)
    wrapped = K.wrap(peer_pub, secret)
    sig = identity.sign(_transcript(wrapped, identity.public_pem(), peer_pem, my_nonce, peer_nonce))
    send_frame(sock, T_KEYX, json.dumps({"wrapped": wrapped.hex(), "sig": sig.hex()}).encode())

    lk = K.derive_layer_keys(secret, my_nonce + peer_nonce)
    return SecureChannel(sock, K.build_cipher(lk), DIR_INITIATOR, DIR_RESPONDER,
                         peer_name, peer_fp, lk)


def handshake_responder(sock, identity: K.Identity, name: str,
                        expected_peer_fp: Optional[str] = None) -> SecureChannel:
    peer_name, peer_pub, peer_pem, peer_nonce, peer_fp = _read_hello(sock, expected_peer_fp)
    hello, my_nonce = _hello(identity, name)
    send_frame(sock, T_HELLO, hello)

    ftype, payload = recv_frame(sock)
    if ftype != T_KEYX:
        raise ProtocolError("expected KEYX")
    data = json.loads(payload)
    wrapped, sig = bytes.fromhex(data["wrapped"]), bytes.fromhex(data["sig"])
    try:
        K.verify(peer_pub, sig, _transcript(wrapped, peer_pem, identity.public_pem(),
                                            peer_nonce, my_nonce))
    except InvalidSignature:
        raise SecurityError("key-exchange signature invalid")
    try:
        secret = identity.unwrap(wrapped)
    except ValueError:
        raise SecurityError("could not unwrap session key")

    lk = K.derive_layer_keys(secret, peer_nonce + my_nonce)
    return SecureChannel(sock, K.build_cipher(lk), DIR_RESPONDER, DIR_INITIATOR,
                         peer_name, peer_fp, lk)
