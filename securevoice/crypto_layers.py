"""Three sequential encryption layers for voice data.

Layer 1: Affine cipher over bytes (mod 256)      -- classical substitution
Layer 2: Row transposition cipher over a block   -- classical permutation
Layer 3: AES-256-GCM                              -- modern authenticated encryption

encrypt = L3(L2(L1(plaintext)))
decrypt = L1^-1(L2^-1(L3^-1(ciphertext)))
"""
from math import gcd
from typing import List, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------- Layer 1: Affine (byte-wise, mod 256) ----------------
class AffineCipher:
    M = 256

    def __init__(self, a: int, b: int):
        if gcd(a, self.M) != 1:
            raise ValueError("a must be coprime with 256 (i.e. odd)")
        self.a = a % self.M
        self.b = b % self.M
        self.a_inv = pow(self.a, -1, self.M)
        self._enc = bytes((self.a * x + self.b) % self.M for x in range(256))
        self._dec = bytes((self.a_inv * (y - self.b)) % self.M for y in range(256))

    def encrypt(self, data: bytes) -> bytes:
        return data.translate(self._enc)

    def decrypt(self, data: bytes) -> bytes:
        return data.translate(self._dec)


# ---------------- Layer 2: Row transposition ----------------
class RowTransposition:
    """Writes data row-by-row into a grid with len(key) columns and reads it
    out column-by-column in the order given by `key` (a permutation of 0..n-1).
    The final partial row is padded; the original length is prefixed (4 bytes)."""

    def __init__(self, key: List[int]):
        if sorted(key) != list(range(len(key))) or len(key) < 2:
            raise ValueError("key must be a permutation of 0..n-1 with n >= 2")
        self.key = list(key)
        self.n = len(key)

    def encrypt(self, data: bytes) -> bytes:
        n = self.n
        body = len(data).to_bytes(4, "big") + data
        pad = (-len(body)) % n
        body += bytes(pad)
        rows = len(body) // n
        out = bytearray()
        for col in self.key:
            out += body[col::n]
        assert len(out) == rows * n
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        n = self.n
        if len(data) % n:
            raise ValueError("ciphertext length not a multiple of key length")
        rows = len(data) // n
        body = bytearray(len(data))
        for i, col in enumerate(self.key):
            body[col::n] = data[i * rows:(i + 1) * rows]
        length = int.from_bytes(body[:4], "big")
        if length > len(body) - 4:
            raise ValueError("corrupt transposition block")
        return bytes(body[4:4 + length])


# ---------------- Layer 3: AES-256-GCM ----------------
class AESLayer:
    NONCE = 12

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._aes = AESGCM(key)

    def encrypt(self, data: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        return self._aes.encrypt(nonce, data, aad)

    def decrypt(self, data: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        # raises cryptography.exceptions.InvalidTag on any tampering
        return self._aes.decrypt(nonce, data, aad)


# ---------------- Combined pipeline ----------------
class LayeredCipher:
    def __init__(self, affine_ab: Tuple[int, int], transposition_key: List[int], aes_key: bytes):
        self.l1 = AffineCipher(*affine_ab)
        self.l2 = RowTransposition(transposition_key)
        self.l3 = AESLayer(aes_key)

    def encrypt(self, data: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        return self.l3.encrypt(self.l2.encrypt(self.l1.encrypt(data)), nonce, aad)

    def decrypt(self, data: bytes, nonce: bytes, aad: bytes = b"") -> bytes:
        return self.l1.decrypt(self.l2.decrypt(self.l3.decrypt(data, nonce, aad)))
