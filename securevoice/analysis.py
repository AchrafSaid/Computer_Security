"""Offline cryptanalysis of the project's own cipher layers (for the report).

Measures how much structure of the original voice survives each layer:
  * statistical: byte entropy, chi-square distance from a uniform distribution
  * pattern:     lag-1 autocorrelation of the data read as 16-bit samples
                 (speech is smooth, so neighbouring samples are strongly correlated)
  * brute force: exhaustive search of the Affine key space (128 x 256 = 32,768 keys)
  * known-plaintext: solve the Affine key (and column order) from known samples
  * chosen-plaintext: encrypt chosen probe messages and read the keys off the output

Intended use: encrypt your own sample audio with 1, 2 and 3 layers and compare.
"""
import math
import os
import time
from collections import Counter
from typing import Callable, List, Optional, Sequence, Tuple

import numpy as np

from .crypto_layers import AESLayer, AffineCipher, RowTransposition


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def chi_square_uniform(data: bytes) -> float:
    """Chi-square statistic of the byte histogram against uniform.
    Truly random data gives about 255 (the degrees of freedom); structure gives far more."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).astype(float)
    expected = len(data) / 256
    return float(((counts - expected) ** 2 / expected).sum())


def lag1_autocorrelation(data: bytes) -> float:
    """Correlation between neighbouring 16-bit samples (close to 1 for speech, ~0 for noise)."""
    x = np.frombuffer(data[: len(data) // 2 * 2], dtype="<i2").astype(float)
    if len(x) < 3 or x.std() == 0:
        return 0.0
    return float(np.corrcoef(x[:-1], x[1:])[0, 1])


def affine_bruteforce(ciphertext: bytes) -> Tuple[Tuple[int, int], float]:
    """Ciphertext-only brute force + statistical scoring over all 32,768 Affine keys.

    In 16-bit speech most samples are small, so the high byte of each sample is
    almost always 0x00 or 0xFF. For a candidate key (a, b) those two plaintext
    values encrypt to b and (255a + b) mod 256, so the key's score is simply how
    often those two ciphertext bytes occur. The score depends only on the byte
    histogram, so it also works when a transposition layer has moved bytes around.
    (Keys that also swap 0x00/0xFF tie with the real key; they give the same audio
    with inverted polarity, which sounds identical.)
    Returns ((a, b), fraction of bytes explained).
    """
    hist = np.bincount(np.frombuffer(ciphertext, dtype=np.uint8), minlength=256)
    best, best_score = (1, 0), -1
    for a in range(1, 256, 2):
        for b in range(256):
            score = hist[b] + hist[(255 * a + b) % 256]
            if score > best_score:
                best, best_score = (a, b), score
    return best, best_score / max(len(ciphertext), 1)


def _untranspose(data: bytes, perm, rows: int, sample_rows: int) -> bytes:
    n = len(perm)
    body = bytearray(sample_rows * n)
    for i, col in enumerate(perm):
        body[col::n] = data[i * rows: i * rows + sample_rows]
    return bytes(body[4:])           # drop the 4-byte length header


def transposition_bruteforce(data: bytes, n_cols: int = 8,
                             sample_rows: int = 4000) -> Tuple[List[int], float]:
    """Tries all n_cols! column orders on the first `sample_rows` rows and keeps
    the one whose output is smoothest (highest lag-1 autocorrelation) -- a pattern attack."""
    from itertools import permutations
    if len(data) % n_cols:
        return list(range(n_cols)), 0.0
    rows = len(data) // n_cols
    k = min(sample_rows, rows)
    best, best_score = list(range(n_cols)), -2.0
    for perm in permutations(range(n_cols)):
        score = lag1_autocorrelation(_untranspose(data, perm, rows, k))
        if score > best_score:
            best, best_score = list(perm), score
    return best, best_score


def similarity(recovered: bytes, original: bytes) -> float:
    """|correlation| between recovered and original samples (1.0 = fully recovered)."""
    a = np.frombuffer(recovered[: len(recovered) // 2 * 2], dtype="<i2").astype(float)
    b = np.frombuffer(original[: len(original) // 2 * 2], dtype="<i2").astype(float)
    n = min(len(a), len(b))
    if n < 3 or a[:n].std() == 0 or b[:n].std() == 0:
        return 0.0
    return float(abs(np.corrcoef(a[:n], b[:n])[0, 1]))


def profile(data: bytes) -> dict:
    return {"entropy": entropy(data), "chi2": chi_square_uniform(data),
            "autocorr": lag1_autocorrelation(data)}


def histogram(data: bytes) -> List[int]:
    return np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256).tolist()


# ---------------------------------------------------------------------------
# Known-plaintext and chosen-plaintext attacks
# ---------------------------------------------------------------------------
def _ints(v) -> np.ndarray:
    if isinstance(v, (bytes, bytearray)):
        return np.frombuffer(bytes(v), dtype=np.uint8).astype(np.int64)
    return np.asarray(v, dtype=np.int64)


def solve_affine(xs: Sequence[int], ys: Sequence[int]) -> Optional[Tuple[int, int]]:
    """Solve y = a*x + b (mod 256) from plaintext/ciphertext byte pairs.
    Two pairs whose plaintexts differ by an odd number give
        a = (y1 - y2) * (x1 - x2)^-1,  b = y1 - a*x1   (mod 256)
    and the key is accepted only if it explains *every* pair."""
    x, y = _ints(xs), _ints(ys)
    if len(x) < 2:
        return None
    odd = np.nonzero((x - x[0]) % 2)[0]
    if not len(odd):
        return None                      # all plaintexts have the same parity: not enough information
    j = odd[0]
    a = int((y[0] - y[j]) * pow(int((x[0] - x[j]) % 256), -1, 256) % 256)
    b = int((y[0] - a * x[0]) % 256)
    if np.all((a * x + b) % 256 == y):
        return a, b
    return None


def _decrypt_classical(ct: bytes, affine: Tuple[int, int], perm: Optional[List[int]]) -> bytes:
    data = ct
    if perm:
        try:
            data = RowTransposition(perm).decrypt(data)
        except ValueError:               # header garbled (e.g. polarity-twin key): rebuild all rows
            rows = len(data) // len(perm)
            data = _untranspose(data, perm, rows, rows)
    return AffineCipher(*affine).decrypt(data)


def known_plaintext_attack(ct: bytes, known: bytes, n_cols: int = 8) -> dict:
    """The attacker knows the first len(known) bytes of the plaintext.
    1. Affine only: the i-th ciphertext byte encrypts the i-th plaintext byte -> solve.
    2. Affine + transposition: the ciphertext is n_cols blocks, one per grid column.
       For every (block, column) pair, line up the known bytes of that column with
       the block and try to solve one Affine key; the pairs that work give the
       column order. 8 x 8 = 64 small checks instead of 8! x 32,768 trials."""
    k = min(len(known), len(ct))
    key = solve_affine(known[:k], ct[:k])
    if key:
        return {"success": True, "affine": key, "perm": None,
                "detail": f"solved a={key[0]} b={key[1]} directly from {k:,} known byte pairs"}
    if len(ct) % n_cols == 0:
        rows = len(ct) // n_cols
        known_rows = min((len(known) + 4) // n_cols, rows)
        perm, keys = [], set()
        for i in range(n_cols):
            block = ct[i * rows:(i + 1) * rows]
            match = None
            for c in range(n_cols):
                r = np.arange(1, known_rows)              # row 0 holds the raw length header
                r = r[r * n_cols + c - 4 < len(known)]
                xs = [known[q * n_cols + c - 4] for q in r]
                ys = [block[q] for q in r]
                kk = solve_affine(xs, ys)
                if kk:
                    match = (c, kk)
                    break
            if not match:
                break
            perm.append(match[0])
            keys.add(match[1])
        if len(perm) == n_cols and sorted(perm) == list(range(n_cols)) and len(keys) == 1:
            key = keys.pop()
            return {"success": True, "affine": key, "perm": perm,
                    "detail": f"solved a={key[0]} b={key[1]} and column order {perm} "
                              f"by matching known bytes to columns (64 checks)"}
    return {"success": False, "affine": None, "perm": None,
            "detail": "no Affine key / column order is consistent with the known bytes "
                      "(the AES layer hides every relation between plaintext and ciphertext)"}


def chosen_plaintext_attack(oracle: Callable[[bytes], bytes], n_cols: int = 8,
                            length: int = 4096) -> dict:
    """The attacker can get chosen messages encrypted (oracle = 'encrypt this for me').
    Probe 1: all 0x00 -> every byte becomes E(0) = b
    Probe 2: all 0x01 -> every byte becomes E(1) = a + b
    Probe 3: byte k of the grid holds its own column number -> after removing the
             Affine layer, output block i is filled with perm[i].
    Finally the recovered keys are checked on a fresh random message."""
    def most_common(d: bytes) -> int:
        return int(np.bincount(np.frombuffer(d, dtype=np.uint8), minlength=256).argmax())

    c0 = oracle(bytes(length))
    det = oracle(bytes(length)) == c0
    b = most_common(c0)
    a = (most_common(oracle(b"\x01" * length)) - b) % 256
    fail = {"success": False, "affine": None, "perm": None, "deterministic": det,
            "detail": ("the same chosen message encrypts differently every time (fresh AES nonce), "
                       "so the probes reveal nothing" if not det else "keys could not be derived")}
    if a % 2 == 0:
        return fail
    aff = AffineCipher(a, b)
    probe = bytes((k + 4) % n_cols for k in range(length))
    c3 = aff.decrypt(oracle(probe))
    perm = None
    if c3 != probe:
        if len(c3) % n_cols:
            return fail
        rows = len(c3) // n_cols
        perm = [most_common(c3[i * rows + 1:(i + 1) * rows]) for i in range(n_cols)]
        if sorted(perm) != list(range(n_cols)):
            return fail
    test = os.urandom(length)
    cipher = (lambda p: RowTransposition(perm).encrypt(aff.encrypt(p))) if perm else aff.encrypt
    if cipher(test) != oracle(test):
        return fail
    return {"success": True, "affine": (a, b), "perm": perm, "deterministic": det,
            "detail": f"3 chosen probes gave a={a} b={b}" + (f", column order {perm}" if perm else "")
                      + "; verified on a fresh random message"}


def ciphertext_only_attack(ct: bytes) -> dict:
    """Brute force + statistics on the Affine layer, then (if the result does not
    yet look like speech) a pattern brute force over all column orders."""
    (a, b), _ = affine_bruteforce(ct)
    stage1 = AffineCipher(a, b).decrypt(ct)
    if lag1_autocorrelation(stage1) > 0.5:          # already smooth -> it is speech
        return {"success": True, "affine": (a, b), "perm": None,
                "detail": f"brute force of 32,768 Affine keys picked a={a} b={b}"}
    perm, score = transposition_bruteforce(stage1)
    ok = score > 0.5
    return {"success": ok, "affine": (a, b), "perm": perm,
            "detail": (f"brute force picked a={a} b={b}, pattern search over 40,320 orders "
                       f"picked {perm} (smoothness {score:.2f})" if ok else
                       f"best guesses a={a} b={b}, columns {perm} still look like noise "
                       f"(smoothness {score:.2f}): the statistics are gone")}


CASES = ("Affine", "Affine + Transposition", "Affine + Transposition + AES")
ATTACKS = ("Ciphertext-only", "Known-plaintext", "Chosen-plaintext")


def make_encryptor(n_layers: int, lk) -> Callable[[bytes], bytes]:
    l1, l2, l3 = AffineCipher(*lk.affine), RowTransposition(lk.transposition), AESLayer(lk.aes)

    def enc(pt: bytes) -> bytes:
        ct = l1.encrypt(pt)
        if n_layers >= 2:
            ct = l2.encrypt(ct)
        if n_layers >= 3:
            ct = l3.encrypt(ct, os.urandom(12))       # fresh nonce per message, as in the real system
        return ct
    return enc


def run_attacks(pcm: bytes, known_bytes: int = 16000, lk=None,
                on_result: Optional[Callable[[dict], None]] = None) -> List[dict]:
    """Encrypt `pcm` with 1, 2 and 3 layers (same random keys) and run all three
    attacks on each. Each result: case, attack, success, key, recovered (0..1),
    secs, detail, audio (what the attacker ends up with)."""
    from .keys import derive_layer_keys
    lk = lk or derive_layer_keys(os.urandom(32), b"lab")
    results = []
    for n, case in enumerate(CASES, 1):
        enc = make_encryptor(n, lk)
        ct = enc(pcm)                                 # the victim's encrypted message
        for attack in ATTACKS:
            t = time.time()
            if attack == "Ciphertext-only":
                r = ciphertext_only_attack(ct)
            elif attack == "Known-plaintext":
                r = known_plaintext_attack(ct, pcm[:known_bytes])
            else:
                r = chosen_plaintext_attack(enc)
            secs = time.time() - t
            audio = _decrypt_classical(ct, r["affine"], r["perm"]) if r["affine"] else ct
            sim = similarity(audio, pcm)
            key = "-"
            if r["affine"]:
                key = f"a={r['affine'][0]} b={r['affine'][1]}" + (f" cols={r['perm']}" if r["perm"] else "")
            res = {"case": case, "layers": n, "attack": attack, "success": r["success"] and sim > 0.9,
                   "key": key, "recovered": sim, "secs": secs, "detail": r["detail"],
                   "audio": audio[: len(audio) // 2 * 2],
                   "real_key": f"a={lk.affine[0]} b={lk.affine[1]}" + (f" cols={lk.transposition}" if n >= 2 else "")}
            results.append(res)
            if on_result:
                on_result(res)
    return results
