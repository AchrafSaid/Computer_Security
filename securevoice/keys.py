"""Key management with a pre-shared passphrase (no public-key cryptography).

Both laptops type the same passphrase, agreed in person beforehand. For every
session both sides pick a fresh random nonce and compute

    master   = PBKDF2-HMAC-SHA256(passphrase, salt = nonce_I || nonce_R, iterations)
    auth key = HKDF-SHA256(master, "auth")
    aes key  = HKDF-SHA256(master, transcript)        (AES-256, the only cipher)

so every session gets a new key although the passphrase stays the same. Each side
proves it knows the passphrase with an HMAC-SHA256 over the handshake transcript;
the passphrase itself is never sent.

The voice is encrypted with AES-256-GCM only. A short passphrase (e.g. a 5-digit
PIN) can be brute-forced from a captured handshake -- that weakness is the subject
of the man-in-the-middle demonstration (see relay.py and analysis.py).
"""
import hashlib
import hmac
from dataclasses import dataclass
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto_layers import AESLayer

TRANSPOSITION_COLS = 8
NONCE_LEN = 16
# Key-stretching rounds for PBKDF2. Real systems use >=200,000 to slow down
# offline guessing. We use a small value so the brute-force MITM demo finishes in
# a second or two; the lesson (a strong passphrase is still safe, a short PIN is
# not) does not depend on this number -- it is the size of the passphrase space.
PBKDF2_ITERATIONS = 1_000
MIN_PASSPHRASE_LEN = 12


def session_master(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=32)


def _hkdf(master: bytes, info: bytes, length: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(master)


def auth_key(master: bytes) -> bytes:
    return _hkdf(master, b"securevoice-v2|auth", 32)


def proof(key: bytes, role: bytes, transcript: bytes) -> bytes:
    """HMAC-SHA256 that shows the sender knows the passphrase (role = b"I" or b"R")."""
    return hmac.new(key, role + transcript, hashlib.sha256).digest()


def check_proof(key: bytes, role: bytes, transcript: bytes, received: bytes) -> bool:
    return hmac.compare_digest(proof(key, role, transcript), received)


def passphrase_warning(passphrase: str) -> str:
    """Empty string if the passphrase looks reasonable, otherwise a warning."""
    if len(passphrase) < MIN_PASSPHRASE_LEN:
        return (f"Passphrase is short ({len(passphrase)} characters). Someone who captures the "
                f"handshake can guess it offline by brute force – use {MIN_PASSPHRASE_LEN}+ "
                "characters, e.g. three random words.")
    return ""


@dataclass
class LayerKeys:
    """The session's AES-256 key.

    `affine` and `transposition` are kept only so the offline cryptanalysis lab
    (analysis.py) can build classical ciphers as attack targets; the live voice
    system in protocol.py uses AES only, via `aes`.
    """
    affine: Tuple[int, int]
    transposition: List[int]
    aes: bytes


def derive_layer_keys(secret: bytes, context: bytes) -> LayerKeys:
    """Expand one session secret into the AES-256 key (plus spare bytes the lab
    turns into classical keys for its cryptanalysis demonstrations)."""
    okm = _hkdf(secret, b"securevoice-v1|" + context, 32 + 2 + 32)
    aes_key = okm[:32]
    a = okm[32] | 1                      # odd => invertible mod 256
    b = okm[33]
    # Fisher-Yates shuffle of column order driven by derived bytes
    perm = list(range(TRANSPOSITION_COLS))
    rnd = okm[34:]
    for i in range(TRANSPOSITION_COLS - 1, 0, -1):
        j = rnd[i] % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return LayerKeys((a, b), perm, aes_key)


def build_cipher(keys: LayerKeys) -> AESLayer:
    """The live cipher is AES-256-GCM only."""
    return AESLayer(keys.aes)
