"""Entry point.

    python run.py peer  [--key keys/peer.pem]     # source or destination laptop
    python run.py relay                           # middle laptop (GUI)
    python run.py relay --cli --listen 12347 --dest 192.168.1.20 --dest-port 12348 --mode tamper
"""
import argparse

from securevoice.peer import DEFAULT_PORT


def main():
    ap = argparse.ArgumentParser(description="SecureVoice – three-layer encrypted voice messaging")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("peer")
    p.add_argument("--key", default="keys/peer.pem", help="RSA identity key file (created if missing)")
    r = sub.add_parser("relay")
    r.add_argument("--cli", action="store_true")
    r.add_argument("--listen", type=int, default=DEFAULT_PORT)
    r.add_argument("--dest", default="127.0.0.1")
    r.add_argument("--dest-port", type=int, default=DEFAULT_PORT + 1)
    r.add_argument("--mode", default="observe")
    r.add_argument("--trigger", type=int, default=5)
    a = ap.parse_args()

    if a.cmd == "peer":
        from securevoice.gui import run_peer
        run_peer(a.key)
    elif a.cli:
        from securevoice.relay import InspectionRelay
        InspectionRelay(a.listen, a.dest, a.dest_port, a.mode, a.trigger).serve_once()
    else:
        from securevoice.gui import run_relay
        run_relay()


if __name__ == "__main__":
    main()
