"""Tkinter GUIs: the voice peer (source / destination laptops) and the
inspection relay (middle laptop). All network callbacks are marshalled onto
the Tk thread through a queue."""
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import analysis
from . import audio
from .keys import Identity
from .peer import DEFAULT_PORT, Peer, VoiceMessage
from .relay import MODES, InspectionRelay


# ---------------------------------------------------------------------------
# Look and feel. macOS keeps its native (Aqua) look, which follows the system
# light/dark setting. On Windows/Linux the default Tk look is plain white, so a
# dark theme matching the Mac is applied instead.
# Override with SECUREVOICE_THEME=dark or SECUREVOICE_THEME=native.
# ---------------------------------------------------------------------------
MONO = ("Menlo", 11) if sys.platform == "darwin" else ("Consolas", 10)
GOOD, BAD, WARN, MUTED = "#4cc26a", "#ff6b6b", "#f0a030", "#9a9a9a"
C = {"bg": "#1f1f1f", "panel": "#2a2a2a", "field": "#2f2f2f", "button": "#3a3a3a",
     "hover": "#474747", "fg": "#e8e8e8", "muted": MUTED, "border": "#454545",
     "accent": "#8e5bd6", "select": "#5b3a99"}


def _use_dark_theme() -> bool:
    choice = os.environ.get("SECUREVOICE_THEME", "").lower()
    if choice in ("dark", "native"):
        return choice == "dark"
    return sys.platform != "darwin"


def _dpi_aware() -> None:
    """Sharp (non-blurry) text on scaled Windows displays. Must run before Tk()."""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def apply_theme(root) -> None:
    if not _use_dark_theme():
        return
    base = ("Segoe UI", 10) if sys.platform == "win32" else ("TkDefaultFont", 10)
    st = ttk.Style(root)
    st.theme_use("clam")
    root.configure(bg=C["bg"])
    st.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["field"],
                 bordercolor=C["border"], lightcolor=C["panel"], darkcolor=C["panel"],
                 troughcolor=C["bg"], focuscolor=C["accent"], selectbackground=C["select"],
                 selectforeground=C["fg"], insertcolor=C["fg"], arrowcolor=C["fg"], font=base)
    st.configure("TLabelframe", background=C["bg"], bordercolor=C["border"], relief="solid")
    st.configure("TLabelframe.Label", background=C["bg"], foreground=C["muted"])
    st.configure("TButton", background=C["button"], padding=(12, 5), relief="flat")
    st.map("TButton",
           background=[("disabled", C["panel"]), ("pressed", C["select"]), ("active", C["hover"])],
           foreground=[("disabled", "#6f6f6f")], bordercolor=[("focus", C["accent"])])
    st.configure("TEntry", padding=5, insertcolor=C["fg"])
    st.map("TEntry", fieldbackground=[("readonly", C["panel"]), ("disabled", C["panel"])],
           foreground=[("disabled", "#777777")], bordercolor=[("focus", C["accent"])])
    st.configure("TCombobox", background=C["button"], padding=4)
    st.map("TCombobox", fieldbackground=[("readonly", C["field"])], foreground=[("readonly", C["fg"])],
           selectbackground=[("readonly", C["field"])], selectforeground=[("readonly", C["fg"])],
           background=[("active", C["hover"])])
    st.configure("TRadiobutton", indicatorcolor=C["field"], indicatorbackground=C["field"])
    st.map("TRadiobutton", indicatorcolor=[("selected", C["accent"])],
           background=[("active", C["bg"])])
    st.configure("Vertical.TScrollbar", background=C["button"], troughcolor=C["panel"],
                 bordercolor=C["panel"], arrowcolor=C["fg"], relief="flat")
    st.map("Vertical.TScrollbar", background=[("active", C["hover"])])
    st.configure("Treeview", background=C["field"], fieldbackground=C["field"], rowheight=26)
    st.configure("Treeview.Heading", background=C["button"], relief="flat", padding=4)
    st.map("Treeview", background=[("selected", C["select"])])
    st.map("Treeview.Heading", background=[("active", C["hover"])])
    for opt, val in (("*Listbox.background", C["field"]), ("*Listbox.foreground", C["fg"]),
                     ("*Listbox.selectBackground", C["select"]), ("*Listbox.selectForeground", C["fg"]),
                     ("*Listbox.relief", "flat"), ("*Listbox.highlightThickness", 1),
                     ("*Listbox.highlightBackground", C["border"]), ("*Listbox.highlightColor", C["accent"]),
                     ("*Text.background", C["panel"]), ("*Text.foreground", C["fg"]),
                     ("*Text.insertBackground", C["fg"]), ("*Text.relief", "flat"),
                     ("*Text.highlightThickness", 1), ("*Text.highlightBackground", C["border"]),
                     ("*Text.selectBackground", C["select"]), ("*Toplevel.background", C["bg"]),
                     ("*TCombobox*Listbox.background", C["field"]),
                     ("*TCombobox*Listbox.foreground", C["fg"]),
                     ("*TCombobox*Listbox.selectBackground", C["select"]),
                     ("*Scrollbar.background", C["button"]), ("*Scrollbar.troughColor", C["bg"])):
        root.option_add(opt, val)


class _ScrolledText(scrolledtext.ScrolledText):
    """ScrolledText with a themed (ttk) scrollbar instead of the plain white one."""

    def __init__(self, master=None, **kw):
        super().__init__(master, **kw)
        self.vbar.destroy()
        self.vbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.yview)
        self.vbar.pack(side="right", fill="y", before=self._w)
        self.configure(yscrollcommand=self.vbar.set)
        if _use_dark_theme():
            self.frame.configure(bg=C["bg"])


def make_root() -> tk.Tk:
    _dpi_aware()
    root = tk.Tk()
    apply_theme(root)
    return root


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
        log = _ScrolledText(parent, height=12, state="disabled", font=MONO)
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
        self.status = ttk.Label(conn, text="Not connected", foreground=MUTED)
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
        self.status.configure(text="Connecting…", foreground=WARN)

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
        self.status.configure(text=f"Secure ↔ {self.peer.channel.peer_name}", foreground=GOOD)
        self.rec_btn.configure(state="normal")
        self.file_btn.configure(state="normal")

    def _on_closed(self, err):
        self.status.configure(text="Disconnected" if not err else "Closed (error)",
                              foreground=BAD if err else MUTED)
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
        secs = len(pcm) / (rate * ch * width)
        if not pcm:
            self.logmsg("Nothing was recorded – check the microphone permission for Terminal/Python")
            return
        self.logmsg(f"Recorded {secs:.1f}s – encrypting and sending…")

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

        heard = ttk.LabelFrame(f, text="Intercepted voice (what the middle laptop hears)", padding=8)
        heard.pack(fill="x", pady=8)
        self.heard = tk.Listbox(heard, height=5)
        self.heard.pack(side="left", fill="both", expand=True)
        hb = ttk.Frame(heard)
        hb.pack(side="left", padx=6)
        ttk.Button(hb, text="▶ Play", command=self.play_intercepted).pack(fill="x")
        ttk.Button(hb, text="■ Stop", command=audio.stop_playback).pack(fill="x", pady=4)
        ttk.Button(hb, text="Cryptanalysis lab…", command=lambda: open_lab(self.root)).pack(fill="x")
        self.relay = None

        self.log = self._make_log(f)
        self.log.pack(fill="both", expand=True, pady=(8, 0))
        self.root.after(1000, self._refresh_heard)

    def _refresh_heard(self):
        if self.relay:
            items = list(self.relay.intercepted)
            self.heard.delete(0, "end")
            for m in items:
                self.heard.insert("end", m.label())
        self.root.after(1000, self._refresh_heard)

    def play_intercepted(self):
        sel = self.heard.curselection()
        if not self.relay or not self.relay.intercepted:
            return
        m = self.relay.intercepted[sel[0] if sel else -1]
        self.post(self._append, self.log,
                  f"[relay] playing intercepted ciphertext as audio ({m.seconds():.1f}s) – "
                  "noise only, the speech cannot be recovered without the session key")
        audio.play(m.as_pcm())

    def start(self):
        try:
            relay = InspectionRelay(int(self.lport.get()), self.dhost.get().strip(),
                                    int(self.dport.get()), self.mode.get(), int(self.trigger.get()),
                                    on_log=lambda t: self.post(self._append, self.log, t))
        except ValueError as e:
            messagebox.showerror("Settings", str(e))
            return
        self.relay = relay
        self.btn.configure(state="disabled")

        def run():
            try:
                relay.serve_once()
            except Exception as e:
                self.post(self._append, self.log, f"[relay] error: {e}")
            self.post(lambda: self.btn.configure(state="normal"))
        threading.Thread(target=run, daemon=True).start()


ATTACK_INFO = {
    "Ciphertext-only": "The attacker has only the ciphertext, exactly what the middle laptop "
                       "captures. Tools: brute force over all keys, byte statistics, and a "
                       "pattern (smoothness) search over all column orders.",
    "Known-plaintext": "The attacker also knows the first {known:.1f} s of the original audio "
                       "(for example a standard greeting) and lines it up with the ciphertext.",
    "Chosen-plaintext": "The attacker can get messages of their choice encrypted with the same "
                        "keys (for example by playing chosen sounds into the sender's microphone) "
                        "and studies the output: all 0x00, all 0x01, then a column-marker pattern.",
}


class LabApp(_QueuedApp):
    """Offline cryptanalysis lab: encrypts one of your recordings with 1, 2 and 3
    layers and runs ciphertext-only, known-plaintext and chosen-plaintext attacks."""

    def __init__(self, root):
        super().__init__(root)
        root.title("SecureVoice – Cryptanalysis lab (offline, on your own recording)")
        self.results, self.pcm, self.rate, self.ch = [], b"", 16000, 1
        f = ttk.Frame(root, padding=10)
        f.pack(fill="both", expand=True)

        cfg = ttk.LabelFrame(f, text="Experiment", padding=8)
        cfg.pack(fill="x")
        self.path = tk.StringVar(value=self._latest_recording())
        self.secs = tk.StringVar(value="20")
        self.known = tk.StringVar(value="0.5")
        ttk.Label(cfg, text="Recording (WAV)").grid(row=0, column=0, sticky="w")
        ttk.Entry(cfg, textvariable=self.path, width=46).grid(row=0, column=1, columnspan=3, sticky="we")
        ttk.Button(cfg, text="Browse…", command=self._browse).grid(row=0, column=4, padx=4)
        ttk.Label(cfg, text="Use first (s)").grid(row=1, column=0, sticky="w")
        ttk.Entry(cfg, textvariable=self.secs, width=6).grid(row=1, column=1, sticky="w")
        ttk.Label(cfg, text="Attacker knows first (s)").grid(row=1, column=2, sticky="e")
        ttk.Entry(cfg, textvariable=self.known, width=6).grid(row=1, column=3, sticky="w")
        self.run_btn = ttk.Button(cfg, text="Run all attacks", command=self.run)
        self.run_btn.grid(row=1, column=4, padx=4)
        self.status = ttk.Label(cfg, text="Keys are random for each run. Nothing is sent on the network.")
        self.status.grid(row=2, column=0, columnspan=5, sticky="w", pady=(6, 0))

        cols = ("layers", "attack", "result", "recovered", "time")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=9)
        for c, title, w in zip(cols, ("Layers", "Attack", "Result", "Voice recovered", "Time"),
                               (230, 140, 120, 120, 70)):
            self.tree.heading(c, text=title)
            self.tree.column(c, width=w, anchor="w")
        self.tree.tag_configure("broken", foreground=BAD)
        self.tree.tag_configure("safe", foreground=GOOD)
        self.tree.pack(fill="x", pady=8)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._show_detail())

        btns = ttk.Frame(f)
        btns.pack(fill="x")
        ttk.Button(btns, text="▶ Play original", command=self.play_original).pack(side="left")
        ttk.Button(btns, text="▶ Play what the attacker recovered", command=self.play_result).pack(side="left", padx=6)
        ttk.Button(btns, text="■ Stop", command=audio.stop_playback).pack(side="left")

        self.detail = _ScrolledText(f, height=8, wrap="word", font=MONO, state="disabled")
        self.detail.pack(fill="both", expand=True, pady=(8, 0))

    @staticmethod
    def _latest_recording() -> str:
        if not os.path.isdir("received"):
            return ""
        wavs = [os.path.join("received", n) for n in os.listdir("received") if n.endswith(".wav")]
        return max(wavs, key=os.path.getmtime) if wavs else ""

    def _browse(self):
        p = filedialog.askopenfilename(filetypes=[("WAV audio", "*.wav")], initialdir="received")
        if p:
            self.path.set(p)

    def run(self):
        try:
            pcm, rate, ch, width = audio.load_wav(self.path.get())
            secs, known = float(self.secs.get()), float(self.known.get())
        except Exception as e:
            messagebox.showerror("Lab", f"Cannot load recording: {e}")
            return
        if width != 2:
            messagebox.showerror("Lab", "Only 16-bit WAV files are supported.")
            return
        self.pcm = pcm[: int(rate * secs) * ch * 2]
        self.rate, self.ch, self.known_secs = rate, ch, known
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.run_btn.configure(state="disabled")
        self.status.configure(text="Running… (the two pattern searches take a few seconds each)")
        known_bytes = int(rate * known) * ch * 2

        def work():
            try:
                analysis.run_attacks(self.pcm, known_bytes, on_result=lambda r: self.post(self._add, r))
                self.post(self.status.configure, {"text": "Done. Select a row for details; play the result to hear it."})
            except Exception as e:
                self.post(self.status.configure, {"text": f"Error: {e}"})
            self.post(lambda: self.run_btn.configure(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    def _add(self, r):
        self.results.append(r)
        self.tree.insert("", "end", iid=str(len(self.results) - 1), tags=("broken" if r["success"] else "safe",),
                         values=(r["case"], r["attack"], "BROKEN" if r["success"] else "resisted",
                                 f"{r['recovered']:.0%}", f"{r['secs']:.2f}s"))

    def _selected(self):
        sel = self.tree.selection()
        return self.results[int(sel[0])] if sel else None

    def _show_detail(self):
        r = self._selected()
        if not r:
            return
        text = (f"{r['attack']} attack on {r['case']}\n\n"
                f"Attacker's position: {ATTACK_INFO[r['attack']].format(known=self.known_secs)}\n\n"
                f"What happened: {r['detail']}.\n\n"
                f"Key the attacker found: {r['key']}\nReal key:              {r['real_key']}"
                + ("\n(A different but equivalent Affine key gives the same audio with inverted polarity.)"
                   if r["success"] and r["key"].split(" cols")[0] != r["real_key"].split(" cols")[0] else "")
                + f"\n\nVoice recovered: {r['recovered']:.0%} (correlation with the original).")
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", text)
        self.detail.configure(state="disabled")

    def play_original(self):
        if self.pcm:
            audio.play(self.pcm, self.rate, self.ch)

    def play_result(self):
        r = self._selected()
        if not r:
            return
        import numpy as np
        pcm = r["audio"]
        if not r["success"]:                     # noise: play at a quarter volume
            pcm = (np.frombuffer(pcm, dtype="<i2") // 4).astype("<i2").tobytes()
        audio.play(pcm, self.rate, self.ch)


def open_lab(master=None):
    LabApp(tk.Toplevel(master) if master else make_root())


def run_lab():
    root = make_root()
    LabApp(root)
    root.mainloop()


def run_peer(key_path: str):
    root = make_root()
    PeerApp(root, key_path)
    root.mainloop()


def run_relay():
    root = make_root()
    RelayApp(root)
    root.mainloop()
