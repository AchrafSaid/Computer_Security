# SecureVoice — CS401 Course Project

Two-way encrypted voice messaging between laptops using **AES-256-GCM**, with the
key derived from a **pre-shared passphrase**, and an **inspection relay** on a
third laptop that sits in the middle. The relay can **brute-force a weak passphrase**,
decrypt the voice, and even **forge a fake message** — a man-in-the-middle demonstration
that shows exactly when strong encryption holds and when it fails.

## Cryptographic model

```
plaintext PCM ─► AES-256-GCM (nonce = dir‖seq, tag over type|dir|seq) ─► wire
wire ─► AES-GCM verify tag + decrypt ─► plaintext PCM
```

One cipher: **AES-256-GCM** (authenticated encryption — confidentiality *and* integrity).

**Key management: pre-shared passphrase** (no public-key cryptography).
1. Before the demo, both users agree on a passphrase and type it into **Shared PIN**.
   It is never sent over the network.
2. On connect, each side sends a fresh 16-byte random nonce in a `HELLO` message.
3. Both sides compute `master = PBKDF2-HMAC-SHA256(passphrase, nonce_I‖nonce_R)` and
   expand it with **HKDF-SHA256** into an authentication key and the AES-256 key.
   New nonces mean a new key every session.
4. **Mutual authentication:** each side sends `HMAC-SHA256(auth key, role‖transcript)`.
   The initiator only sends its proof after the responder's proof checks out.

**Integrity:** every frame is authenticated by GCM over the ciphertext plus its
type, direction and sequence number; sequence numbers must increase by exactly 1,
so modified, reordered, replayed or dropped frames are rejected; each voice message
also carries an end-to-end SHA-256 hash.

> **The catch (this is the whole point).** AES-256-GCM cannot be broken. But its key
> is only as strong as the passphrase. If the two laptops share a short PIN (e.g.
> `12345`), a man in the middle who captured the handshake can try every PIN, derive
> the key exactly as the peers did, and confirm it against the handshake's HMAC proof —
> about 10,000 guesses, under a second. Then the attacker holds the key and can decrypt
> and forge at will, undetected. A long passphrase cannot be guessed, so the attacker
> never gets in and tampering is caught. **Weak key = total break; strong key = safe.**

(For a fast demonstration, PBKDF2 uses a low iteration count. Real systems use
≥200,000 rounds; that only changes how long each guess takes, not the conclusion —
the security against a strong passphrase comes from the size of the passphrase space.)

## Setup (on each laptop)

Use Python 3.10+ with Tk 8.6 or newer. On macOS the built-in `/usr/bin/python3` ships
Tk 8.5, which draws blank windows, so install one with Tk instead:
`brew install python@3.12 python-tk@3.12`, then use `python3.12` below.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Running the 3-laptop demo

All three laptops must be on the same network. Each GUI shows its own IP.

| Laptop | Command | Settings |
|---|---|---|
| Destination | `.venv/bin/python run.py peer` | Role **Listen**, port `12348` |
| Middle (relay) | `.venv/bin/python run.py relay` | Listen `12347`, destination = Destination IP : `12348` |
| Source | `.venv/bin/python run.py peer` | Role **Connect**, IP = relay IP, port `12347` |

1. Type the same **Shared PIN** on the source and the destination. Use a 5-digit PIN
   (e.g. `12345`) to demonstrate the attack, or a long passphrase to stay secure.
   The relay does **not** need it.
2. Start the destination, then the relay, then the source.
3. Press **● Record**, speak for about 1 minute, then **■ Stop & Send**. Both directions
   work at the same time. Received messages are saved in `received/`.

### Relay (man-in-the-middle) modes

Passive:
- `observe`: forward unchanged, log each frame and its entropy, save the ciphertext.
- `crack`: brute-force the PIN from the captured handshake, **decrypt the real voice**
  and save it as `recovered_*.wav`. The message still reaches the destination unchanged —
  a passive tap, so neither side notices. Press **▶ Decrypted** to hear it.

Active:
- `tamper` / `replay` / `drop`: corrupt / re-send / delete one DATA frame. With a strong
  key the attacker has no key, so the destination's AES-GCM / sequence checks **reject**
  the message (a **SECURITY ALERT**). This shows the defence working.
- `forge`: when a peer starts transmitting (either direction), the relay **detects it**,
  drops the real message, and brute-forces the PIN. The attacker then **records a fake live** (press
  ●  Record → ■  Stop & inject) — or pre-stages one with *Browse…* — and it is re-encrypted
  with the recovered key and sent to the destination. Because the attacker holds the key,
  the forged frames pass every check, so the destination plays the fake and **neither side
  notices**.

Command-line relay:
```bash
.venv/bin/python run.py relay --cli --listen 12347 --dest <destination-ip> --dest-port 12348 --mode crack
.venv/bin/python run.py relay --cli --mode forge --fake fake.wav --dest <destination-ip> --dest-port 12348
```

## Tests

```bash
.venv/bin/python -m pytest -v
```
- `tests/test_unit.py`: AES-GCM, key derivation, HMAC proofs, the handshake (right and
  wrong passphrase), framing, and **brute force recovering a weak PIN**.
- `tests/test_integration.py`: real localhost TCP. Two-way sending, a 60-second message,
  a wrong passphrase being rejected, the relay's tamper/replay/drop being **detected**,
  and the weak-key **crack** (decrypt the real voice) and **forge** (inject a fake the
  destination accepts) attacks.
- `tests/test_analysis.py`: the offline cryptanalysis lab (classical ciphers as attack
  targets) — ciphertext-only, known-plaintext and chosen-plaintext attacks all break the
  classical layers and all fail once AES is added.

## Project layout

```
securevoice/crypto_layers.py   AES-256-GCM (+ classical ciphers used as lab attack targets)
securevoice/keys.py            passphrase key management: PBKDF2, HKDF, HMAC proofs
securevoice/protocol.py        framing, handshake, SecureChannel (AES-GCM, seq/replay checks)
securevoice/peer.py            two-way voice peer (reader thread + thread-safe send)
securevoice/relay.py           man-in-the-middle relay: observe, crack, tamper/replay/drop, forge
securevoice/audio.py           mic recording / playback / WAV
securevoice/gui.py             Tkinter GUIs (peer, relay, cryptanalysis lab)
securevoice/analysis.py        offline cryptanalysis + the PIN brute-force attack
run.py                         entry point
```

## Known limitations
- Security depends entirely on the passphrase. A short PIN is broken in seconds (that is
  the demonstration); use 12+ characters, e.g. three random words, to stay safe. The GUI
  warns below 12 characters.
- The passphrase must be shared in person beforehand. There is no forward secrecy: anyone
  who learns the passphrase later can decrypt recorded sessions.
- PBKDF2 uses a low iteration count so the brute-force demo is fast; a deployed system
  would use ≥200,000 rounds.

## Cryptanalysis (for the report)

### 1. The real attack — brute force the passphrase (against AES)

AES-256-GCM is not broken; the **key** is. The relay in `crack` / `forge` mode captures the
handshake, tries every PIN, derives the key the same way the peers did, and confirms it
against the handshake's HMAC proof.

| Passphrase | Guesses | Time (demo settings) | Result |
|---|---|---|---|
| 5-digit PIN (`12345`, the demo) | ≤ 100,000 | ~4–8 s | **key recovered → decrypt + forge, undetected** |
| 4-digit PIN | ≤ 10,000 | < 1 s | broken instantly |
| 6-digit PIN | ≤ 1,000,000 | ~40–80 s | still broken |
| 12-char random passphrase | ~10²¹ | infeasible | **safe** — attacker never gets the key |

(With the real PBKDF2 of 200,000 rounds each guess is ~200× slower, so even a 6-digit
PIN would take hours — which is why key-stretching exists.)

Because the attacker ends up with the real key, the forged message passes AES-GCM's tag
check and the sequence check, so the destination accepts it and raises no alert. The same
tamper/replay/drop attempt **without** the key (a strong passphrase) is rejected — that
contrast is the core result.

### 2. Classical cryptanalysis techniques (offline lab)

`.venv/bin/python run.py lab` (or **Cryptanalysis lab…** in the relay window) encrypts one
of your recordings with 1, 2 and 3 classical layers (Affine, Row transposition, then AES)
and runs the rubric's attack types against each. It shows that these techniques recover the
voice from the classical ciphers but learn **nothing** once AES is added — nothing is sent
on the network.

| Attack | What the attacker has | Classical layers | With AES |
|---|---|---|---|
| **Ciphertext-only** (brute force + statistics + pattern) | only the ciphertext | broken | 0% |
| **Known-plaintext** | the first ~0.5 s of audio and its ciphertext | broken | 0% |
| **Chosen-plaintext** | can get chosen messages encrypted | broken | 0% |

**Why AES stops all of these:** its output is statistically random (so there is nothing to
measure), known pairs do not reveal the key, and a fresh nonce per frame means the same
message encrypts differently every time. The only way past AES is a weak key — section 1.

**Outputs:** `analysis/results.csv`, `attacks.csv`, `histograms.csv` (for charts), and
`recovered_layers<N>_<attack>.wav` (what the attacker ends up with).
