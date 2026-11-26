"""Layer-by-layer cryptanalysis of your own recording, for the report.

    .venv/bin/python scripts/cryptanalysis_report.py received/msg1_XXXX.wav

Encrypts the WAV with 1, 2 and 3 layers (random keys), measures entropy,
chi-square and lag-1 autocorrelation, then runs three attacks on each case:
  * ciphertext-only  - brute force (32,768 Affine keys) + statistics + pattern
                       search over all 8! = 40,320 column orders
  * known-plaintext  - attacker knows the first 0.5 s of the audio
  * chosen-plaintext - attacker gets chosen probe messages encrypted
The same attacks are available in the GUI: python run.py lab
Writes analysis/results.csv, analysis/attacks.csv, analysis/histograms.csv
and analysis/recovered_*.wav.
"""
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securevoice import analysis as A                      # noqa: E402
from securevoice.audio import load_wav, save_wav            # noqa: E402
from securevoice.keys import derive_layer_keys              # noqa: E402

OUT = "analysis"
SECONDS = 20
KNOWN_SECONDS = 0.5


def main(path: str) -> None:
    pcm, rate, ch, width = load_wav(path)
    pcm = pcm[: rate * width * ch * SECONDS]
    lk = derive_layer_keys(os.urandom(32), b"analysis")
    os.makedirs(OUT, exist_ok=True)
    print(f"Input: {path} ({len(pcm) / rate / width / ch:.1f}s)")
    print(f"Real keys: Affine a={lk.affine[0]} b={lk.affine[1]}, columns {lk.transposition}\n")

    # 1. statistics of each ciphertext
    cases = {name: A.make_encryptor(n, lk)(pcm) for n, name in enumerate(A.CASES, 1)}
    print(f"{'case':32} {'entropy':>7} {'chi2':>11} {'autocorr':>8}")
    stats = [["plaintext", *A.profile(pcm).values()]]
    stats += [[name, *A.profile(ct).values()] for name, ct in cases.items()]
    for row in stats:
        print(f"{row[0]:32} {row[1]:7.3f} {row[2]:11.0f} {row[3]:8.3f}")

    # 2. attacks
    print(f"\n{'case':32} {'attack':17} {'result':9} {'recovered':>9} {'time':>7}  key found")
    results = A.run_attacks(pcm, known_bytes=int(rate * KNOWN_SECONDS) * ch * width, lk=lk)
    for r in results:
        print(f"{r['case']:32} {r['attack']:17} {'BROKEN' if r['success'] else 'resisted':9} "
              f"{r['recovered']:9.0%} {r['secs']:6.2f}s  {r['key']}")
        tag = r["attack"].split("-")[0].lower()
        save_wav(os.path.join(OUT, f"recovered_layers{r['layers']}_{tag}.wav"), r["audio"], rate, ch, width)

    with open(os.path.join(OUT, "results.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case", "entropy_bits_per_byte", "chi_square", "lag1_autocorr"])
        w.writerows(stats)
    with open(os.path.join(OUT, "attacks.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case", "attack", "broken", "voice_recovered", "seconds", "key_found", "real_key", "detail"])
        for r in results:
            w.writerow([r["case"], r["attack"], r["success"], round(r["recovered"], 4), round(r["secs"], 3),
                        r["key"], r["real_key"], r["detail"]])
    with open(os.path.join(OUT, "histograms.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["byte", "plaintext"] + list(cases))
        hists = [A.histogram(pcm)] + [A.histogram(d) for d in cases.values()]
        for i in range(256):
            w.writerow([i] + [h[i] for h in hists])
    print("\n'recovered' = |correlation| between the attacker's output and the real voice.")
    print(f"Saved {OUT}/results.csv, {OUT}/attacks.csv, {OUT}/histograms.csv and {OUT}/recovered_*.wav")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
