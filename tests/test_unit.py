"""Unit tests: each layer, the combined cipher, key handling and framing."""
import os
import socket

import pytest
import threading

from cryptography.exceptions import InvalidTag

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


# ---------- Keys (pre-shared passphrase) ----------
def test_session_master_depends_on_passphrase_and_salt():
    salt = os.urandom(32)
    m = K.session_master("blue river 42 tiger", salt, iterations=1000)
    assert m == K.session_master("blue river 42 tiger", salt, iterations=1000) and len(m) == 32
    assert m != K.session_master("blue river 42 tigeR", salt, iterations=1000)   # one letter differs
    assert m != K.session_master("blue river 42 tiger", os.urandom(32), iterations=1000)
    with pytest.raises(ValueError):
        K.session_master("", salt)


def test_proof_hmac():
    key, t = os.urandom(32), os.urandom(32)
    p = K.proof(key, b"I", t)
    assert K.check_proof(key, b"I", t, p)
    assert not K.check_proof(key, b"R", t, p)                 # roles are not interchangeable
    assert not K.check_proof(os.urandom(32), b"I", t, p)      # wrong key
    assert not K.check_proof(key, b"I", os.urandom(32), p)    # different session


def test_derive_layer_keys_deterministic_and_valid():
    s = os.urandom(32)
    a, b = K.derive_layer_keys(s, b"ctx"), K.derive_layer_keys(s, b"ctx")
    assert a == b
    assert a.affine[0] % 2 == 1
    assert sorted(a.transposition) == list(range(K.TRANSPOSITION_COLS))
    assert K.derive_layer_keys(s, b"other").aes != a.aes


def test_passphrase_warning():
    assert K.passphrase_warning("short")
    assert K.passphrase_warning("correct horse battery staple") == ""


def _handshake(pass_i, pass_r):
    a, b = socket.socketpair()
    out = {}

    def resp():
        try:
            out["r"] = P.handshake_responder(b, pass_r, "bob")
        except Exception as e:
            out["r"] = e
    t = threading.Thread(target=resp)
    t.start()
    try:
        out["i"] = P.handshake_initiator(a, pass_i, "alice")
    except Exception as e:
        out["i"] = e
        a.close()
    t.join(10)
    return out["i"], out["r"]


def test_handshake_same_passphrase_gives_same_fresh_keys():
    i, r = _handshake("correct horse battery staple", "correct horse battery staple")
    assert i.layer_keys == r.layer_keys and i.peer_name == "bob" and r.peer_name == "alice"
    i2, r2 = _handshake("correct horse battery staple", "correct horse battery staple")
    assert i2.layer_keys.aes != i.layer_keys.aes                 # new nonces -> new session keys
    i.send(b"hello"); assert r.recv() == b"hello"
    for c in (i, r, i2, r2):
        c.close()


def test_handshake_wrong_passphrase_rejected_on_both_sides():
    i, r = _handshake("correct horse battery staple", "wrong horse battery staple")
    assert isinstance(i, P.SecurityError) and "passphrase" in str(i)
    assert isinstance(r, P.SecurityError) and "passphrase" in str(r)


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
