"""Tkinter GUIs: the voice peer (source / destination laptops) and the
inspection relay (middle laptop). All network callbacks are marshalled onto
the Tk thread through a queue."""
import os
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import audio
from .keys import Identity
from .peer import DEFAULT_PORT, Peer, VoiceMessage
from .relay import MODES, InspectionRelay


def local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


class _QueuedApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: "queue.Queue" = queue.Queue()
        root.after(100, self._drain)

    def post(self, fn, *args):
        self.q.put((fn, args))

    def _drain(self):
        try:
            while True:
                fn, args = self.q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _make_log(self, parent):
        log = scrolledtext.ScrolledText(parent, height=12, state="disabled", font=("Menlo", 11))
        return log

    def _append(self, widget, text):
        widget.configure(state="normal")
        widget.insert("end", time.strftime("[%H:%M:%S] ") + text + "\n")
        widget.see("end")
        widget.configure(state="disabled")


class PeerApp(_QueuedApp):
    def __init__(self, root: tk.Tk, key_path: str):
        super().__init__(root)
        root.title("SecureVoice – Peer")
        self.identity = Identity.load_or_create(key_path)
        self.peer = None
        self.recorder = audio.Recorder()
        self.rec_start = None
        self.received = []  # list[VoiceMessage]
        os.makedirs("received", exist_ok=True)
        self._build()

    # ---------- layout ----------
    def _build(self):
        f = ttk.Frame(self.root, padding=10)
        f.pack(fill="both", expand=True)

        conn = ttk.LabelFrame(f, text="Connection", padding=8)
        conn.pack(fill="x")
        self.name = tk.StringVar(value=socket.gethostname().split(".")[0])
        self.role = tk.StringVar(value="listen")
        self.host = tk.StringVar(value="127.0.0.1")
        self.port = tk.StringVar(value=str(DEFAULT_PORT))
        self.pin = tk.StringVar()
        ttk.Label(conn, text="Name").grid(row=0, column=0, sticky="w")
        ttk.Entry(conn, textvariable=self.name, width=18).grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(conn, text="Listen (destination)", variable=self.role,
                        value="listen").grid(row=0, column=2, padx=8)
        ttk.Radiobutton(conn, text="Connect (source)", variable=self.role,
                        value="connect").grid(row=0, column=3)
        ttk.Label(conn, text="Peer / relay IP").grid(row=1, column=0, sticky="w")
        ttk.Entry(conn, textvariable=self.host, width=18).grid(row=1, column=1, sticky="w")
        ttk.Label(conn, text="Port").grid(row=1, column=2, sticky="e")
        ttk.Entry(conn, textvariable=self.port, width=8).grid(row=1, column=3, sticky="w")
        ttk.Label(conn, text="Pinned peer fingerprint").grid(row=2, column=0, sticky="w")
        ttk.Entry(conn, textvariable=self.pin, width=48).grid(row=2, column=1, columnspan=3, sticky="we")
        ttk.Label(conn, text="My fingerprint").grid(row=3, column=0, sticky="w")
        fp = ttk.Entry(conn, width=48)
        fp.insert(0, self.identity.fingerprint())
        fp.configure(state="readonly")
        fp.grid(row=3, column=1, columnspan=3, sticky="we")
        ttk.Label(conn, text=f"My IP: {local_ip()}").grid(row=4, column=0, columnspan=2, sticky="w")
        self.start_btn = ttk.Button(conn, text="Start", command=self.start)
        self.start_btn.grid(row=4, column=3, sticky="e")
        self.status = ttk.Label(conn, text="Not connected", foreground="gray")
        self.status.grid(row=4, column=2)

        voice = ttk.LabelFrame(f, text="Voice messages", padding=8)
        voice.pack(fill="x", pady=8)
        self.rec_btn = ttk.Button(voice, text="● Record", command=self.toggle_record, state="disabled")
        self.rec_btn.pack(side="left")
        self.timer = ttk.Label(voice, text="00:00")
        self.timer.pack(side="left", padx=8)
        self.file_btn = ttk.Button(voice, text="Send WAV file…", command=self.send_file, state="disabled")
        self.file_btn.pack(side="left", padx=8)

        inbox = ttk.LabelFrame(f, text="Received", padding=8)
        inbox.pack(fill="both", expand=True)
        self.inbox = tk.Listbox(inbox, height=6)
        self.inbox.pack(side="left", fill="both", expand=True)
        btns = ttk.Frame(inbox)
        btns.pack(side="left", padx=6)
        ttk.Button(btns, text="▶ Play", command=self.play_selected).pack(fill="x")
        ttk.Button(btns, text="■ Stop", command=audio.stop_playback).pack(fill="x", pady=4)

        self.log = self._make_log(f)
        self.log.pack(fill="both", expand=True, pady=(8, 0))
        self.root.protocol("WM_DELETE_WINDOW", self.quit)

    def logmsg(self, text):
        self.post(self._append, self.log, text)

    # ---------- connection ----------
    def start(self):
        try:
            port = int(self.port.get())
        except ValueError:
            messagebox.showerror("Port", "Port must be a number")
            return
        self.peer = Peer(self.identity, self.name.get() or "peer",
                         on_voice=lambda m: self.post(self._on_voice, m),
                         on_text=lambda s, t: self.logmsg(f"{s}: {t}"),
                         on_log=self.logmsg,
                         on_closed=lambda e: self.post(self._on_closed, e))
        pin = self.pin.get().strip() or None
        if not pin:
            self.logmsg("WARNING: no pinned fingerprint – compare the peer fingerprint "
                        "shown below with the other laptop before trusting the session.")
        self.start_btn.configure(state="disabled")
        self.status.configure(text="Connecting…", foreground="orange")

        def run():
            try:
                if self.role.get() == "listen":
                    self.peer.listen_and_accept(port, expected_peer_fp=pin)
                else:
                    self.peer.connect(self.host.get().strip(), port, expected_peer_fp=pin)
                self.post(self._on_connected)
            except Exception as e:
                self.logmsg(f"Handshake failed: {e}")
                self.post(self._on_closed, e)
        threading.Thread(target=run, daemon=True).start()

    def _on_connected(self):
        self.status.configure(text=f"Secure ↔ {self.peer.channel.peer_name}", foreground="green")
        self.rec_btn.configure(state="normal")
        self.file_btn.configure(state="normal")

    def _on_closed(self, err):
        self.status.configure(text="Disconnected" if not err else "Closed (error)",
                              foreground="red" if err else "gray")
        self.rec_btn.configure(state="disabled")
        self.file_btn.configure(state="disabled")
        self.start_btn.configure(state="normal")

    # ---------- voice ----------
    def toggle_record(self):
        if self.rec_start is None:
            try:
                self.recorder.start()
            except Exception as e:
                messagebox.showerror("Microphone", str(e))
                return
            self.rec_start = time.time()
            self.rec_btn.configure(text="■ Stop & Send")
            self._tick()
        else:
            pcm = self.recorder.stop()
            self.rec_start = None
            self.rec_btn.configure(text="● Record")
            self._send(pcm, audio.SAMPLE_RATE, audio.CHANNELS, audio.SAMPLE_WIDTH)

    def _tick(self):
        if self.rec_start is not None:
            s = int(time.time() - self.rec_start)
            self.timer.configure(text=f"{s // 60:02d}:{s % 60:02d}")
            self.root.after(250, self._tick)

    def send_file(self):
        path = filedialog.askopenfilename(filetypes=[("WAV audio", "*.wav")])
        if path:
            pcm, rate, ch, width = audio.load_wav(path)
            self._send(pcm, rate, ch, width)

    def _send(self, pcm, rate, ch, width):
        def run():
            try:
                self.peer.send_voice(pcm, rate, ch, width)
            except Exception as e:
                self.logmsg(f"Send failed: {e}")
        threading.Thread(target=run, daemon=True).start()

    def _on_voice(self, m: VoiceMessage):
        path = os.path.join("received", time.strftime(f"msg{m.msg_id}_%H%M%S.wav"))
        audio.save_wav(path, m.pcm, m.sample_rate, m.channels, m.sample_width)
        self.received.append(m)
        self.inbox.insert("end", f"#{m.msg_id} from {m.sender} – {m.duration:.1f}s – {path}")

    def play_selected(self):
        sel = self.inbox.curselection()
        if sel:
            m = self.received[sel[0]]
            audio.play(m.pcm, m.sample_rate, m.channels)

    def quit(self):
        if self.peer:
            self.peer.close()
        self.root.destroy()


class RelayApp(_QueuedApp):
    def __init__(self, root: tk.Tk):
        super().__init__(root)
        root.title("SecureVoice – Inspection Relay (middle laptop)")
        f = ttk.Frame(root, padding=10)
        f.pack(fill="both", expand=True)
        cfg = ttk.LabelFrame(f, text="Relay settings", padding=8)
        cfg.pack(fill="x")
        self.lport = tk.StringVar(value=str(DEFAULT_PORT))
        self.dhost = tk.StringVar(value="127.0.0.1")
        self.dport = tk.StringVar(value=str(DEFAULT_PORT + 1))
        self.mode = tk.StringVar(value="observe")
        self.trigger = tk.StringVar(value="5")
        rows = [("Listen port", self.lport), ("Destination IP", self.dhost),
                ("Destination port", self.dport), ("Trigger DATA frame #", self.trigger)]
        for i, (lbl, var) in enumerate(rows):
            ttk.Label(cfg, text=lbl).grid(row=i, column=0, sticky="w")
            ttk.Entry(cfg, textvariable=var, width=18).grid(row=i, column=1, sticky="w")
        ttk.Label(cfg, text="Mode").grid(row=4, column=0, sticky="w")
        ttk.Combobox(cfg, textvariable=self.mode, values=MODES, state="readonly",
                     width=16).grid(row=4, column=1, sticky="w")
        ttk.Label(cfg, text=f"My IP: {local_ip()}").grid(row=5, column=0, sticky="w")
        self.btn = ttk.Button(cfg, text="Start relay", command=self.start)
        self.btn.grid(row=5, column=1, sticky="e")
        self.log = self._make_log(f)
        self.log.pack(fill="both", expand=True, pady=(8, 0))

    def start(self):
        try:
            relay = InspectionRelay(int(self.lport.get()), self.dhost.get().strip(),
                                    int(self.dport.get()), self.mode.get(), int(self.trigger.get()),
                                    on_log=lambda t: self.post(self._append, self.log, t))
        except ValueError as e:
            messagebox.showerror("Settings", str(e))
            return
        self.btn.configure(state="disabled")

        def run():
            try:
                relay.serve_once()
            except Exception as e:
                self.post(self._append, self.log, f"[relay] error: {e}")
            self.post(lambda: self.btn.configure(state="normal"))
        threading.Thread(target=run, daemon=True).start()


def run_peer(key_path: str):
    root = tk.Tk()
    PeerApp(root, key_path)
    root.mainloop()


def run_relay():
    root = tk.Tk()
    RelayApp(root)
    root.mainloop()
