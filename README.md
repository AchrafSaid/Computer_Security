# SecureVoice — CS401 Course Project

Two-way encrypted voice messaging between laptops, using **three cryptographic layers in sequence**, keys from a **pre-shared passphrase**, and an **inspection relay** on a third laptop that sits between them.

## Cryptographic model

```
plaintext PCM ─► L1 Affine (mod 256) ─► L2 Row Transposition ─► L3 AES-256-GCM ─► wire
wire ─► L3⁻¹ AES-GCM (verify tag) ─► L2⁻¹ ─► L1⁻¹ ─► plaintext PCM
```

| Layer | Algorithm | Key | Purpose |
|---|---|---|---|
| L1 | Affine `E(x) = (a·x + b) mod 256`, `a` odd | (a, b) | Classical substitution on bytes |
| L2 | Row transposition, 8 columns | column permutation | Classical permutation |
| L3 | AES-256-GCM | 256-bit key, nonce = dir‖seq | Confidentiality + integrity |

**Key management: pre-shared passphrase** (no public-key cryptography).
1. Before the demo, the two users agree on a passphrase in person, and both type it into **Shared passphrase**. It is never sent over the network.
2. On connect, each side sends a fresh 16-byte random nonce in a `HELLO` message.
3. Both sides compute `master = PBKDF2-HMAC-SHA256(passphrase, nonce_I‖nonce_R, 200,000 rounds)`. **HKDF-SHA256** then expands it into an authentication key and all three layer keys. New nonces mean new keys every session.
4. **Mutual authentication:** each side sends `HMAC-SHA256(auth key, role‖transcript)`. The initiator only sends its proof after the responder's proof checks out. A wrong passphrase, or a man in the middle without it, means the connection is refused on both sides.

**Integrity:**
- Every frame is authenticated by GCM over the ciphertext plus its type, direction and sequence number.
- Sequence numbers must increase by exactly 1, so replayed, reordered or dropped frames are rejected.
- Each voice message also carries an end-to-end SHA-256 hash.

## Setup (on each laptop)

Use Python 3.10+ with Tk 8.6 or newer. On macOS the built-in `/usr/bin/python3` ships Tk 8.5, which draws blank windows, so install one with Tk instead: `brew install python@3.12 python-tk@3.12`, then use `python3.12` below.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Running the 3-laptop demo

All three laptops must be on the same network. Each GUI shows its own IP.

| Laptop | Command | Settings |
|---|---|---|
| Destination | `.venv/bin/python run.py peer` | Role **Listen**, port `12348` |
| Middle (relay) | `.venv/bin/python run.py relay` | Listen `12347`, destination = Destination IP : `12348`, mode `observe` |
| Source | `.venv/bin/python run.py peer` | Role **Connect**, IP = relay IP, port `12347` |

1. Type the same **Shared passphrase** on the source and the destination. Use 12+ characters, for example three random words. The relay doesn't need it.
2. Start the destination, then the relay, then the source.
3. Press **● Record**, speak for about 1 minute, then press **■ Stop & Send**. Do the same from the other side; both directions work at the same time.
4. Received messages are saved in `received/` and can be played from the list.

Relay modes for the evaluation chapter:
- `observe`: logs each frame and its entropy, and saves the ciphertext in `captures/`.
- `tamper`, `replay`, `drop`: modify the traffic at one frame (set by *Trigger DATA frame #*). The destination must show a **SECURITY ALERT** and refuse the message.

A command-line relay is also available:
```bash
.venv/bin/python run.py relay --cli --listen 12347 --dest <destination-ip> --dest-port 12348 --mode tamper
```

## Tests

```bash
.venv/bin/python -m pytest -v
```
- `tests/test_unit.py`: each layer, the combined cipher, passphrase key derivation, HMAC proofs, the handshake (right and wrong passphrase), and framing.
- `tests/test_integration.py`: real localhost TCP connections. Covers two-way sending at the same time, a 60-second message, a wrong passphrase being rejected, and the relay in observe, tamper, replay and drop modes.
- `tests/test_analysis.py`: the cryptanalysis. Ciphertext-only, known-plaintext and chosen-plaintext attacks all break the classical layers, and all three fail once AES is added.

## Project layout

```
securevoice/crypto_layers.py   three cipher layers + LayeredCipher
securevoice/keys.py            passphrase key management: PBKDF2, HKDF, HMAC proofs
securevoice/protocol.py        framing, handshake, SecureChannel (seq/replay checks)
securevoice/peer.py            two-way voice peer (reader thread + thread-safe send)
securevoice/relay.py           inspection relay for the middle laptop
securevoice/audio.py           mic recording / playback / WAV
securevoice/gui.py             Tkinter GUIs (peer, relay, cryptanalysis lab)
securevoice/analysis.py        offline cryptanalysis (statistics + three attack types)
run.py                         entry point
```

## Known limitations
- Security depends on the passphrase. An attacker who captures a handshake can try to guess it offline, which PBKDF2 with 200,000 rounds slows down, so use a long one. The GUI warns below 12 characters.
- The passphrase must be shared in person beforehand. There is no forward secrecy: anyone who learns the passphrase later can decrypt recorded sessions.
- The Affine and transposition layers are weak on their own. Security comes from AES-GCM, and the classical layers are there for the course's layered-model requirement and for the cryptanalysis discussion.

## Cryptanalysis (for the report)

Your recording is encrypted with 1, 2 and 3 layers, using fresh random keys for each run. Three classic attacks are then run against each case. This is an offline lab: nothing is sent on the network.

- **GUI:** `.venv/bin/python run.py lab`, or the **Cryptanalysis lab…** button in the relay window.
- **Command line:** `.venv/bin/python scripts/cryptanalysis_report.py received/<your-message>.wav`

| Attack | What the attacker has | How the classical layers fall |
|---|---|---|
| **Ciphertext-only** | only the ciphertext | **Brute force + statistics:** tries all 32,768 Affine keys and scores each by the byte histogram. In speech the high bytes are mostly `0x00`/`0xFF`. **Pattern:** tries all 8! = 40,320 column orders and keeps the smoothest output. |
| **Known-plaintext** | the first 0.5 s of audio and its ciphertext | Two byte pairs solve `a = (y1−y2)(x1−x2)⁻¹`, `b = y1 − a·x1 (mod 256)`. Matching the known bytes against each ciphertext block reveals the column order in 64 checks. |
| **Chosen-plaintext** | can get chosen messages encrypted | All-`0x00` gives `b`, all-`0x01` gives `a+b`. A column-marker message then shows the column order directly. |

Example result (8.4 s recording):

| Layers | Entropy | Chi-square | Ciphertext-only | Known-plaintext | Chosen-plaintext |
|---|---|---|---|---|---|
| Plaintext | 6.24 | 3,579,319 | – | – | – |
| Affine | 6.24 | 3,579,319 | broken, 100% | broken, 100% | broken, 100% |
| Affine + Transposition | 6.24 | 3,579,261 | broken, 100% (~3 s) | broken, 100% | broken, 100% |
| Affine + Transposition + AES | 8.00 | ≈220 | **0%** | **0%** | **0%** |

**Why AES stops all three:**
- AES-GCM output is statistically random, so the ciphertext-only attacks have nothing to measure.
- Known plaintext–ciphertext pairs don't reveal the AES key.
- Every frame uses a new nonce, so the same chosen message encrypts differently each time.

**Outputs:**
- In `analysis/`: `results.csv` (statistics), `attacks.csv` (attack outcomes) and `histograms.csv`. Use these for charts.
- `recovered_layers<N>_<attack>.wav`: what the attacker ends up with.
