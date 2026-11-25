"""RSA identity keys, key wrapping (RSA-OAEP), signatures (RSA-PSS) and
derivation of the three layer keys from one session secret (HKDF-SHA256)."""
import hashlib
import os
from dataclasses import dataclass
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .crypto_layers import LayeredCipher

SESSION_SECRET_LEN = 32
TRANSPOSITION_COLS = 8

_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


class Identity:
    """An RSA-2048 key pair, optionally persisted to a PEM file."""

    def __init__(self, private_key: rsa.RSAPrivateKey):
        self.private_key = private_key
        self.public_key = private_key.public_key()

    @classmethod
    def generate(cls) -> "Identity":
        return cls(rsa.generate_private_key(public_exponent=65537, key_size=2048))

    @classmethod
    def load_or_create(cls, path: str) -> "Identity":
        if os.path.exists(path):
            with open(path, "rb") as f:
                return cls(serialization.load_pem_private_key(f.read(), password=None))
        ident = cls.generate()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "wb") as f:
            f.write(ident.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        os.chmod(path, 0o600)
        return ident

    def public_pem(self) -> bytes:
        return public_pem(self.public_key)

    def fingerprint(self) -> str:
        return fingerprint(self.public_pem())

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data, _PSS, hashes.SHA256())

    def unwrap(self, wrapped: bytes) -> bytes:
        return self.private_key.decrypt(wrapped, _OAEP)


def public_pem(pub: rsa.RSAPublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM,
                            serialization.PublicFormat.SubjectPublicKeyInfo)


def load_public(pem: bytes) -> rsa.RSAPublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size < 2048:
        raise ValueError("peer key must be RSA >= 2048 bits")
    return key


def fingerprint(pem: bytes) -> str:
    """Short human-comparable fingerprint (SHA-256, first 16 bytes, hex groups)."""
    h = hashlib.sha256(pem).hexdigest()[:32].upper()
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


def wrap(pub: rsa.RSAPublicKey, secret: bytes) -> bytes:
    return pub.encrypt(secret, _OAEP)


def verify(pub: rsa.RSAPublicKey, signature: bytes, data: bytes) -> None:
    """Raises cryptography.exceptions.InvalidSignature on failure."""
    pub.verify(signature, data, _PSS, hashes.SHA256())


@dataclass
class LayerKeys:
    affine: Tuple[int, int]
    transposition: List[int]
    aes: bytes


def derive_layer_keys(secret: bytes, context: bytes) -> LayerKeys:
    """Expand one session secret into independent keys for all three layers."""
    okm = HKDF(algorithm=hashes.SHA256(), length=32 + 2 + 32, salt=None,
               info=b"securevoice-v1|" + context).derive(secret)
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


def build_cipher(keys: LayerKeys) -> LayeredCipher:
    return LayeredCipher(keys.affine, keys.transposition, keys.aes)
