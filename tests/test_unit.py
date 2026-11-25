"""Unit tests: each layer, the combined cipher, key handling and framing."""
import os
import socket

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag

from securevoice import keys as K
from securevoice import protocol as P
from securevoice.crypto_layers import AESLayer, AffineCipher, LayeredCipher, RowTransposition
from securevoice.relay import shannon_entropy

SAMPLES = [b"", b"A", b"HELLO WORLD", bytes(range(256)), os.urandom(5000)]


# ---------- Layer 1: Affine ----------
@pytest.mark.parametrize("data", SAMPLES)
def test_affine_roundtrip(data):
    c = AffineCipher(77, 201)
    assert c.decrypt(c.encrypt(data)) == data


def test_affine_known_vector():
    # E(x) = (5x + 8) mod 256 ; x=0 -> 8, x=1 -> 13, x=255 -> (1275+8)%256 = 3
    assert AffineCipher(5, 8).encrypt(bytes([0, 1, 255])) == bytes([8, 13, 3])


def test_affine_rejects_even_a():
    with pytest.raises(ValueError):
        AffineCipher(4, 1)


def test_affine_is_bijection():
    c = AffineCipher(3, 7)
    assert sorted(c.encrypt(bytes(range(256)))) == list(range(256))


# ---------- Layer 2: Row transposition ----------
@pytest.mark.parametrize("data", SAMPLES)
def test_transposition_roundtrip(data):
    t = RowTransposition([3, 1, 4, 0, 2])
    assert t.decrypt(t.encrypt(data)) == data


def test_transposition_permutes_only():
    t = RowTransposition([1, 0])
    data = b"ABCDEFGH"
    ct = t.encrypt(data)
    body = len(data).to_bytes(4, "big") + data       # 12 bytes, no padding
    assert sorted(ct) == sorted(body) and ct != body


def test_transposition_bad_key():
    for key in ([0], [0, 0], [1, 2]):
        with pytest.raises(ValueError):
            RowTransposition(key)


# ---------- Layer 3: AES-GCM ----------
def test_aes_roundtrip_and_tamper():
    aes = AESLayer(os.urandom(32))
    n = os.urandom(12)
    ct = aes.encrypt(b"secret voice", n, b"hdr")
    assert aes.decrypt(ct, n, b"hdr") == b"secret voice"
    bad = bytearray(ct); bad[0] ^= 1
    with pytest.raises(InvalidTag):
        aes.decrypt(bytes(bad), n, b"hdr")
    with pytest.raises(InvalidTag):
        aes.decrypt(ct, n, b"other-hdr")


def test_aes_wrong_key_size():
    with pytest.raises(ValueError):
        AESLayer(b"short")


# ---------- Combined ----------
@pytest.mark.parametrize("data", SAMPLES)
def test_layered_roundtrip(data):
    c = LayeredCipher((9, 33), [2, 0, 3, 1], os.urandom(32))
    n = os.urandom(12)
    assert c.decrypt(c.encrypt(data, n), n) == data


def test_layered_ciphertext_looks_random():
    c = LayeredCipher((9, 33), [2, 0, 3, 1], os.urandom(32))
    ct = c.encrypt(bytes(20000), os.urandom(12))          # all-zero "silence"
    assert shannon_entropy(ct) > 7.9                       # max is 8 bits/byte


# ---------- Keys ----------
@pytest.fixture(scope="module")
def ident():
    return K.Identity.generate()


def test_wrap_unwrap(ident):
    s = os.urandom(32)
    assert ident.unwrap(K.wrap(ident.public_key, s)) == s


def test_sign_verify(ident):
    sig = ident.sign(b"data")
    K.verify(ident.public_key, sig, b"data")
    with pytest.raises(InvalidSignature):
        K.verify(ident.public_key, sig, b"datA")


def test_derive_layer_keys_deterministic_and_valid():
    s = os.urandom(32)
    a, b = K.derive_layer_keys(s, b"ctx"), K.derive_layer_keys(s, b"ctx")
    assert a == b
    assert a.affine[0] % 2 == 1
    assert sorted(a.transposition) == list(range(K.TRANSPOSITION_COLS))
    assert K.derive_layer_keys(s, b"other").aes != a.aes


def test_fingerprint_format(ident):
    fp = ident.fingerprint()
    assert len(fp.split(":")) == 8 and fp == K.fingerprint(ident.public_pem())


def test_identity_persisted(tmp_path):
    p = str(tmp_path / "k.pem")
    assert K.Identity.load_or_create(p).fingerprint() == K.Identity.load_or_create(p).fingerprint()


# ---------- Framing ----------
def test_frame_roundtrip():
    a, b = socket.socketpair()
    P.send_frame(a, P.T_DATA, b"xyz")
    assert P.recv_frame(b) == (P.T_DATA, b"xyz")
    a.close(); b.close()


def test_parse_frames_partial():
    a, b = socket.socketpair()
    raw = bytearray()
    for i in range(3):
        raw += (4).to_bytes(4, "big") + bytes([P.T_DATA]) + bytes([i] * 3)
    buf = bytearray(raw[:10])
    got = list(P.parse_frames(buf))
    assert len(got) == 1 and len(buf) == 2
    buf += raw[10:]
    assert [p for _, p, _ in P.parse_frames(buf)] == [bytes([1] * 3), bytes([2] * 3)]
    a.close(); b.close()
