"""Cryptanalysis tests: the classical layers alone are breakable, all three are not."""
import math
import os
import struct

import pytest

from securevoice import analysis as A
from securevoice.crypto_layers import AESLayer, AffineCipher, RowTransposition


@pytest.fixture(scope="module")
def speech():
    """Quiet, smooth signal like real speech (|sample| < 256 -> high byte 0x00/0xFF)."""
    n = 16000 * 3
    return b"".join(struct.pack("<h", int(180 * math.sin(i / 9) + 60 * math.sin(i / 3.7)))
                    for i in range(n))


KEY_A, KEY_T = (77, 140), [3, 6, 0, 7, 1, 5, 2, 4]


def test_affine_keeps_statistics(speech):
    ct = AffineCipher(*KEY_A).encrypt(speech)
    assert abs(A.entropy(ct) - A.entropy(speech)) < 1e-9          # histogram only relabelled
    assert abs(A.chi_square_uniform(ct) - A.chi_square_uniform(speech)) < 1e-6


def test_affine_alone_is_broken(speech):
    ct = AffineCipher(*KEY_A).encrypt(speech)
    (a, b), _ = A.affine_bruteforce(ct)
    assert A.similarity(AffineCipher(a, b).decrypt(ct), speech) > 0.99


def test_affine_plus_transposition_is_broken(speech):
    ct = RowTransposition(KEY_T).encrypt(AffineCipher(*KEY_A).encrypt(speech))
    (a, b), _ = A.affine_bruteforce(ct)
    stage1 = AffineCipher(a, b).decrypt(ct)
    perm, _ = A.transposition_bruteforce(stage1)
    assert perm == KEY_T
    rec = A._untranspose(stage1, perm, len(stage1) // 8, len(stage1) // 8)
    assert A.similarity(rec, speech) > 0.99


def test_all_three_layers_resist(speech):
    ct = AESLayer(os.urandom(32)).encrypt(
        RowTransposition(KEY_T).encrypt(AffineCipher(*KEY_A).encrypt(speech)), os.urandom(12))
    assert A.entropy(ct) > 7.99
    assert A.chi_square_uniform(ct) < 400                         # ~255 expected for random
    assert abs(A.lag1_autocorrelation(ct)) < 0.05
    (a, b), _ = A.affine_bruteforce(ct)
    assert A.similarity(AffineCipher(a, b).decrypt(ct), speech) < 0.05


def test_metrics_on_known_inputs():
    assert A.entropy(bytes(1000)) == 0.0
    assert abs(A.entropy(bytes(range(256)) * 10) - 8.0) < 1e-9
    assert A.chi_square_uniform(bytes(range(256)) * 10) == 0.0
    assert A.similarity(b"\x01\x00\x05\x00\x02\x00", b"\x01\x00\x05\x00\x02\x00") == pytest.approx(1.0)


# ---------------- known-plaintext and chosen-plaintext ----------------
def _three_layer_oracle():
    aes = AESLayer(os.urandom(32))
    return lambda p: aes.encrypt(RowTransposition(KEY_T).encrypt(AffineCipher(*KEY_A).encrypt(p)),
                                 os.urandom(12))


def test_solve_affine_from_two_pairs():
    e = AffineCipher(*KEY_A).encrypt(bytes([0, 1]))
    assert A.solve_affine([0, 1], list(e)) == KEY_A
    assert A.solve_affine([0, 2], list(AffineCipher(*KEY_A).encrypt(bytes([0, 2])))) is None  # even gap: ambiguous
    assert A.solve_affine([0, 1, 2], [1, 2, 200]) is None                                     # inconsistent pairs


def test_known_plaintext_breaks_affine(speech):
    ct = AffineCipher(*KEY_A).encrypt(speech)
    r = A.known_plaintext_attack(ct, speech[:2000])
    assert r["success"] and r["affine"] == KEY_A and r["perm"] is None


def test_known_plaintext_breaks_affine_plus_transposition(speech):
    ct = RowTransposition(KEY_T).encrypt(AffineCipher(*KEY_A).encrypt(speech))
    r = A.known_plaintext_attack(ct, speech[:2000])
    assert r["success"] and r["affine"] == KEY_A and r["perm"] == KEY_T


def test_known_plaintext_fails_with_aes(speech):
    ct = _three_layer_oracle()(speech)
    assert not A.known_plaintext_attack(ct, speech[:2000])["success"]


def test_chosen_plaintext_breaks_classical_layers():
    oracle = lambda p: RowTransposition(KEY_T).encrypt(AffineCipher(*KEY_A).encrypt(p))
    r = A.chosen_plaintext_attack(oracle)
    assert r["success"] and r["affine"] == KEY_A and r["perm"] == KEY_T and r["deterministic"]


def test_chosen_plaintext_fails_with_aes():
    r = A.chosen_plaintext_attack(_three_layer_oracle())
    assert not r["success"] and not r["deterministic"]     # same input -> different ciphertext


def test_lab_runs_every_attack_on_every_case(speech):
    results = A.run_attacks(speech, known_bytes=2000)
    assert len(results) == 9
    for r in results:
        assert r["success"] == (r["layers"] < 3), (r["case"], r["attack"], r["detail"])
