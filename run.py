"""Entry point.

    python run.py peer                            # source or destination laptop
    python run.py relay                           # middle laptop / man in the middle (GUI)
    python run.py lab                             # offline cryptanalysis lab (GUI)
    python run.py relay --cli --listen 12347 --dest 192.168.1.20 --dest-port 12348 --mode crack
    python run.py relay --cli --mode forge --fake fake.wav --dest 192.168.1.20 --dest-port 12348
"""
import argparse

from securevoice.peer import DEFAULT_PORT


def main():
    ap = argparse.ArgumentParser(description="SecureVoice – three-layer encrypted voice messaging")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("peer")
    sub.add_parser("lab")
    r = sub.add_parser("relay")
    r.add_argument("--cli", action="store_true")
    r.add_argument("--listen", type=int, default=DEFAULT_PORT)
    r.add_argument("--dest", default="127.0.0.1")
    r.add_argument("--dest-port", type=int, default=DEFAULT_PORT + 1)
    r.add_argument("--mode", default="observe")
    r.add_argument("--trigger", type=int, default=5)
    r.add_argument("--fake", default=None, help="WAV file to inject in forge mode")
    a = ap.parse_args()

    if a.cmd == "lab":
        from securevoice.gui import run_lab
        run_lab()
    elif a.cmd == "peer":
        from securevoice.gui import run_peer
        run_peer()
    elif a.cli:
        from securevoice.relay import InspectionRelay
        fake_pcm, fake_rate = None, 16000
        if a.fake:
            from securevoice.audio import load_wav
            fake_pcm, fake_rate, _, _ = load_wav(a.fake)
        InspectionRelay(a.listen, a.dest, a.dest_port, a.mode, a.trigger,
                        fake_pcm=fake_pcm, fake_rate=fake_rate).serve_once()
    else:
        from securevoice.gui import run_relay
        run_relay()


if __name__ == "__main__":
    main()
