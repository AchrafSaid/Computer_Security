# SecureVoice — CS401 Course Project

Two-way encrypted voice messaging between laptops, using **three cryptographic layers in sequence**, an **RSA key exchange**, and an **inspection relay** on a third laptop that sits between them.

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

**Key management:** every laptop has an RSA-2048 identity (`keys/peer.pem`, created on first run).
1. Both sides exchange `HELLO` messages containing their public key and a random nonce.
2. The initiator generates a 32-byte session secret, wraps it with **RSA-OAEP** to the responder's key, and signs it with **RSA-PSS**. The signature covers both public keys and both nonces.
3. Both sides derive all three layer keys from the secret with **HKDF-SHA256**.
4. Each side can **pin** the other's fingerprint (compared by reading it aloud or showing the screen). A mismatch aborts the connection.

**Integrity:**
- Every frame is authenticated by GCM over the ciphertext plus its type, direction and sequence number.
- Sequence numbers must increase by exactly 1, so replayed, reordered or dropped frames are rejected.
- Each voice message also carries an end-to-end SHA-256 hash.

## Setup (on each laptop)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Running the 3-laptop demo

All three laptops must be on the same network. Each GUI shows its own IP.

| Laptop | Command | Settings |
|---|---|---|
| Destination | `.venv/bin/python run.py peer` | Role **Listen**, port `12348` |
| Middle (relay) | `.venv/bin/python run.py relay` | Listen `12347`, destination = Destination IP : `12348`, mode `observe` |
| Source | `.venv/bin/python run.py peer` | Role **Connect**, IP = relay IP, port `12347` |

1. Exchange fingerprints between source and destination and paste them into **Pinned peer fingerprint**.
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
- `tests/test_unit.py`: each layer, the combined cipher, RSA wrap and sign, key derivation, and framing.
- `tests/test_integration.py`: real localhost TCP connections. Covers two-way sending at the same time, a 60-second message, fingerprint mismatch, and the relay in observe, tamper, replay and drop modes.

## Project layout

```
securevoice/crypto_layers.py   three cipher layers + LayeredCipher
securevoice/keys.py            RSA identity, OAEP, PSS, HKDF layer-key derivation
securevoice/protocol.py        framing, handshake, SecureChannel (seq/replay checks)
securevoice/peer.py            two-way voice peer (reader thread + thread-safe send)
securevoice/relay.py           inspection relay for the middle laptop
securevoice/audio.py           mic recording / playback / WAV
securevoice/gui.py             Tkinter GUIs
run.py                         entry point
```

## Known limitations
- Without a pinned fingerprint, the first connection trusts whatever key is presented (trust on first use). The GUI warns about this. Always pin fingerprints for the demo.
- The Affine and transposition layers are weak on their own. Security comes from AES-GCM, and the classical layers are there for the course's layered-model requirement and for the cryptanalysis discussion.
