"""Integration tests over real TCP sockets on localhost:
source <-> destination directly, and source <-> relay <-> destination,
including the relay's tamper / replay / drop test modes."""
import math
import struct
import threading
import time

import pytest

from securevoice.peer import Peer
from securevoice.relay import InspectionRelay

RATE = 16000


def tone(seconds: float, freq: float) -> bytes:
    n = int(RATE * seconds)
    return b"".join(struct.pack("<h", int(12000 * math.sin(2 * math.pi * freq * i / RATE)))
                    for i in range(n))


PASS = "correct horse battery staple"


@pytest.fixture(scope="module")
def ids():
    return PASS, PASS                   # both laptops typed the same shared passphrase


class Harness:
    def __init__(self):
        self.voices, self.closed, self.logs = [], [], []
        self.got = threading.Event()
        self.ended = threading.Event()

    def peer(self, passphrase, name):
        def on_voice(m):
            self.voices.append(m); self.got.set()

        def on_closed(e):
            self.closed.append(e); self.ended.set()
        return Peer(passphrase, name, on_voice=on_voice, on_log=self.logs.append, on_closed=on_closed)


def start_dest(dest, port=0):
    ready = threading.Event()
    errs = []

    def run():
        try:
            dest.listen_and_accept(port, host="127.0.0.1", timeout=10, ready=ready)
        except Exception as e:
            errs.append(e)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    ready.wait(5)
    return dest._listener.getsockname()[1], t, errs


def wait_for(pred, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


def test_direct_full_duplex(ids):
    hs, hd = Harness(), Harness()
    src, dst = hs.peer(ids[0], "alice"), hd.peer(ids[1], "bob")
    port, t, _ = start_dest(dst)
    src.connect("127.0.0.1", port)
    t.join(5)
    a, b = tone(2.0, 440), tone(1.5, 660)
    # send both directions at the same time
    th = threading.Thread(target=src.send_voice, args=(a, RATE))
    th.start(); dst.send_voice(b, RATE); th.join()
    assert wait_for(lambda: hd.voices and hs.voices)
    assert hd.voices[0].pcm == a and hs.voices[0].pcm == b
    assert hd.voices[0].sender == "alice" and abs(hd.voices[0].duration - 2.0) < 0.01
    src.close(); dst.close()


def test_one_minute_message(ids):
    hs, hd = Harness(), Harness()
    src, dst = hs.peer(ids[0], "alice"), hd.peer(ids[1], "bob")
    port, t, _ = start_dest(dst)
    src.connect("127.0.0.1", port); t.join(5)
    pcm = tone(1.0, 300) * 60                     # 60 s, ~1.9 MB
    src.send_voice(pcm, RATE)
    assert wait_for(lambda: hd.voices, 30)
    assert hd.voices[0].pcm == pcm and abs(hd.voices[0].duration - 60) < 0.01
    src.close(); dst.close()


def test_wrong_passphrase_rejected(ids):
    """A peer (or a man in the middle) without the right passphrase cannot connect."""
    hs, hd = Harness(), Harness()
    src, dst = hs.peer("a guessed passphrase!", "mallory"), hd.peer(ids[1], "bob")
    port, t, errs = start_dest(dst)
    with pytest.raises(Exception, match="passphrase"):
        src.connect("127.0.0.1", port)
    t.join(5)
    assert errs and "passphrase" in str(errs[0])
    assert dst.channel is None
    src.close(); dst.close()


def run_via_relay(ids, mode, trigger=3):
    hs, hd = Harness(), Harness()
    src, dst = hs.peer(ids[0], "alice"), hd.peer(ids[1], "bob")
    dport, t, _ = start_dest(dst)
    logs = []
    relay = InspectionRelay(0, "127.0.0.1", dport, mode, trigger, capture_dir=None, on_log=logs.append)
    ready = threading.Event()
    threading.Thread(target=relay.serve_once, args=(ready,), daemon=True).start()
    ready.wait(5)
    src.connect("127.0.0.1", relay.listen_port); t.join(5)
    pcm = tone(3.0, 500)                           # ~96 KB -> several chunks
    try:
        src.send_voice(pcm, RATE)
    except OSError:
        pass
    wait_for(lambda: hd.voices or hd.ended.is_set(), 10)
    src.close(); dst.close()
    return hd, pcm, logs


def test_relay_observe_passes_through(ids):
    hd, pcm, logs = run_via_relay(ids, "observe")
    assert hd.voices and hd.voices[0].pcm == pcm
    assert any("entropy=" in l for l in logs)


def test_relay_hears_noise_not_speech(ids):
    """The middle laptop captures roughly as much 'audio' as was sent, but it is
    ciphertext: uncorrelated with the original signal and close to max entropy."""
    import numpy as np
    from securevoice.relay import InspectionRelay, shannon_entropy
    hs, hd = Harness(), Harness()
    src, dst = hs.peer(ids[0], "alice"), hd.peer(ids[1], "bob")
    dport, t, _ = start_dest(dst)
    relay = InspectionRelay(0, "127.0.0.1", dport, "observe", capture_dir=None, on_log=lambda s: None)
    ready = threading.Event()
    threading.Thread(target=relay.serve_once, args=(ready,), daemon=True).start()
    ready.wait(5)
    src.connect("127.0.0.1", relay.listen_port); t.join(5)
    pcm = tone(3.0, 440)
    src.send_voice(pcm, RATE)
    assert wait_for(lambda: hd.voices)
    src.close(); dst.close()
    assert wait_for(lambda: relay.done.is_set(), 5)

    heard = [m for m in relay.intercepted if m.direction == "A->B"]
    assert len(heard) == 1
    m = heard[0]
    assert abs(m.seconds() - 3.0) < 0.2                      # about as long as the speech
    assert shannon_entropy(bytes(m.data)) > 7.99              # looks random
    orig = np.frombuffer(pcm, dtype="<i2").astype(float)
    noise = np.frombuffer(bytes(m.data[:len(pcm)]), dtype="<i2").astype(float)
    n = min(len(orig), len(noise))
    corr = abs(np.corrcoef(orig[:n], noise[:n])[0, 1])
    assert corr < 0.05                                        # no trace of the original signal


@pytest.mark.parametrize("mode,expected", [
    ("tamper", "integrity check failed"),
    ("replay", "replayed"),
    ("drop", "missing frame"),
])
def test_relay_attacks_detected(ids, mode, expected):
    hd, pcm, logs = run_via_relay(ids, mode)
    assert not hd.voices, "modified stream must not be delivered"
    assert any(expected in l for l in hd.logs), hd.logs
