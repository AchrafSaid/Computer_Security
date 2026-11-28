"""Tkinter GUIs: the voice peer (source / destination laptops), the inspection
relay (middle laptop) and the offline cryptanalysis lab. All network callbacks
are marshalled onto the Tk thread through a queue.

Design direction: exact, calm, a little forensic – a signals lab at night.
Neutral ink-grey surfaces, one teal accent for the primary action and the
session's keys, amber only for warnings and the attacker, red/green only for
results. Signature: the waveform bars of the logo, reused in the mic meter."""
import hashlib
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, scrolledtext, ttk

from . import analysis
from . import audio
from .keys import passphrase_warning
from .peer import DEFAULT_PORT, Peer, VoiceMessage
from .relay import MODES, InspectionRelay, shannon_entropy

# ---------------------------------------------------------------------------
# Design tokens
# ---------------------------------------------------------------------------
C = {"bg": "#0e0f13", "card": "#15161b", "field": "#1d1f25", "button": "#24262d",
     "hover": "#2d3038", "border": "#26272d", "fg": "#ececef", "secondary": "#a3a6af",
     "muted": "#7f838d", "faint": "#5c606a", "ink": "#0b0d11"}
ACCENT = "#3cc9b5"                                   # teal: primary action + session keys
GOOD, BAD, WARN, MUTED = "#4cc38a", "#e5484d", "#e5a33b", C["muted"]
ACCENTS = {"peer": ACCENT, "relay": ACCENT, "lab": ACCENT}
MAC = sys.platform == "darwin"
WIN = sys.platform == "win32"
MONO = ("Menlo", 12) if MAC else ("Consolas", 10)
F = {}  # fonts, filled in by apply_theme()


def _mix(c1: str, c2: str, t: float) -> str:
    """Blend colour c1 towards c2 by t (0 = c1, 1 = c2)."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def _dpi_aware() -> None:
    """Sharp (non-blurry) text on scaled Windows displays. Must run before Tk()."""
    if WIN:
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass


def apply_theme(root) -> None:
    fam = tkfont.nametofont("TkDefaultFont").actual("family")
    base = 12 if MAC else 10
    F.update(base=(fam, base), small=(fam, base - 1), bold=(fam, base, "bold"),
             section=(fam, base), title=(fam, base + 5),
             value=(fam, base + 8), mono=MONO, mono_small=(MONO[0], MONO[1] - 1),
             timer=(MONO[0], base + 8))
    st = ttk.Style(root)
    st.theme_use("clam")
    root.configure(bg=C["bg"])
    st.configure(".", background=C["bg"], foreground=C["fg"], fieldbackground=C["field"],
                 bordercolor=C["border"], lightcolor=C["field"], darkcolor=C["field"],
                 troughcolor=C["field"], focuscolor=C["hover"], selectbackground=C["hover"],
                 selectforeground=C["fg"], insertcolor=C["fg"], arrowcolor=C["muted"], font=F["base"])
    # surfaces and text
    st.configure("TFrame", background=C["bg"])
    st.configure("Card.TFrame", background=C["card"])
    st.configure("TLabel", background=C["bg"])
    st.configure("Title.TLabel", font=F["title"])
    st.configure("Sub.TLabel", foreground=C["secondary"], font=F["small"])
    st.configure("Card.TLabel", background=C["card"])
    st.configure("Label.Card.TLabel", background=C["card"], foreground=C["secondary"], font=F["small"])
    st.configure("Muted.Card.TLabel", background=C["card"], foreground=C["muted"], font=F["small"])
    st.configure("Section.Card.TLabel", background=C["card"], foreground=C["fg"], font=F["section"])
    st.configure("Value.Card.TLabel", background=C["card"], font=F["value"])
    st.configure("Timer.Card.TLabel", background=C["card"], font=F["timer"])
    # controls
    flat = dict(bordercolor=C["border"], lightcolor=C["button"], darkcolor=C["button"], relief="flat")
    st.configure("TButton", background=C["button"], padding=(16, 4), **flat)
    st.map("TButton", background=[("disabled", C["field"]), ("pressed", C["hover"]), ("active", C["hover"])],
           foreground=[("disabled", C["faint"])], lightcolor=[("active", C["hover"])],
           darkcolor=[("active", C["hover"])])
    st.configure("TEntry", padding=4, lightcolor=C["field"], darkcolor=C["field"])
    st.map("TEntry", fieldbackground=[("disabled", C["card"])], foreground=[("disabled", C["faint"])],
           bordercolor=[("disabled", C["border"])])
    st.configure("TCombobox", background=C["button"], padding=4, lightcolor=C["field"], darkcolor=C["field"])
    st.map("TCombobox", fieldbackground=[("readonly", C["field"])], foreground=[("readonly", C["fg"])],
           selectbackground=[("readonly", C["field"])], selectforeground=[("readonly", C["fg"])],
           background=[("active", C["hover"])])
    st.configure("Vertical.TScrollbar", background=C["button"], troughcolor=C["field"],
                 bordercolor=C["field"], lightcolor=C["button"], darkcolor=C["button"],
                 arrowcolor=C["muted"], relief="flat", gripcount=0)
    st.map("Vertical.TScrollbar", background=[("active", C["hover"])])
    rows = tkfont.Font(font=F["base"]).metrics("linespace")
    st.configure("Treeview", background=C["field"], fieldbackground=C["field"], borderwidth=0,
                 rowheight=int(rows * 1.55), lightcolor=C["field"], darkcolor=C["field"])
    st.configure("Treeview.Heading", background=C["card"], foreground=C["secondary"], relief="flat",
                 padding=(8, 4), font=F["small"], lightcolor=C["card"], darkcolor=C["card"])
    st.map("Treeview", background=[("selected", C["hover"])])
    st.map("Treeview.Heading", background=[("active", C["card"])])
    for opt, val in (("*Listbox.background", C["field"]), ("*Listbox.foreground", C["fg"]),
                     ("*Listbox.selectBackground", C["hover"]), ("*Listbox.selectForeground", C["fg"]),
                     ("*Listbox.relief", "flat"), ("*Listbox.borderWidth", 0),
                     ("*Listbox.highlightThickness", 0), ("*Listbox.activeStyle", "none"),
                     ("*Text.background", C["field"]), ("*Text.foreground", C["fg"]),
                     ("*Text.insertBackground", C["fg"]), ("*Text.relief", "flat"),
                     ("*Text.borderWidth", 0), ("*Text.highlightThickness", 0),
                     ("*Text.selectBackground", C["hover"]), ("*Toplevel.background", C["bg"]),
                     ("*TCombobox*Listbox.background", C["field"]),
                     ("*TCombobox*Listbox.foreground", C["fg"]),
                     ("*TCombobox*Listbox.selectBackground", C["hover"])):
        root.option_add(opt, val)


def _accent_styles(root, key: str) -> str:
    """Per-window accent variants of the buttons, toggles and inputs."""
    acc = ACCENTS[key]
    st = ttk.Style(root)
    k = key.capitalize()
    for name, colour in ((f"{k}.Accent.TButton", acc), (f"{k}.Danger.TButton", BAD)):
        st.configure(name, background=colour, foreground=C["ink"], font=F["base"], padding=(20, 6),
                     bordercolor=colour, lightcolor=colour, darkcolor=colour)
        hi = _mix(colour, "#ffffff", 0.18)
        st.map(name, background=[("disabled", C["field"]), ("pressed", _mix(colour, "#000000", 0.15)),
                                 ("active", hi)],
               foreground=[("disabled", C["faint"])],
               bordercolor=[("disabled", C["border"]), ("active", hi)],
               lightcolor=[("disabled", C["field"]), ("active", hi)],
               darkcolor=[("disabled", C["field"]), ("active", hi)])
    sel = C["hover"]                                  # selection is a neutral surface step
    st.configure(f"{k}.Seg.Toolbutton", background=C["field"], foreground=C["secondary"], padding=(16, 4),
                 anchor="center", bordercolor=C["border"], lightcolor=C["field"], darkcolor=C["field"])
    st.map(f"{k}.Seg.Toolbutton", background=[("selected", sel), ("active", C["button"])],
           foreground=[("selected", C["fg"])], bordercolor=[("selected", _mix(C["fg"], C["card"], 0.75))],
           lightcolor=[("selected", sel)], darkcolor=[("selected", sel)])
    st.configure(f"{k}.TEntry")
    st.map(f"{k}.TEntry", bordercolor=[("focus", acc), ("disabled", C["border"])],
           fieldbackground=[("disabled", C["card"])], foreground=[("disabled", C["faint"])])
    st.configure(f"{k}.TCheckbutton", background=C["card"], foreground=C["secondary"], font=F["small"],
                 indicatorcolor=C["field"], indicatorbackground=C["field"])
    st.map(f"{k}.TCheckbutton", indicatorcolor=[("selected", C["secondary"])], background=[("active", C["card"])])
    return k


class _ScrolledText(scrolledtext.ScrolledText):
    """ScrolledText with a themed (ttk) scrollbar instead of the plain white one."""

    def __init__(self, master=None, **kw):
        kw.setdefault("padx", 12)
        kw.setdefault("pady", 8)
        super().__init__(master, **kw)
        self.vbar.destroy()
        self.vbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.yview)
        self.vbar.pack(side="right", fill="y", before=self._w)
        self.configure(yscrollcommand=self.vbar.set)
        self.frame.configure(bg=C["field"])


# ---------------------------------------------------------------------------
# Small custom widgets
# ---------------------------------------------------------------------------
def _round_rect(cv, x1, y1, x2, y2, r, **kw):
    pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
           x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return cv.create_polygon(pts, smooth=True, **kw)


class Pill(tk.Canvas):
    """Quiet status: a coloured dot and plain text, no capsule."""

    def __init__(self, master, bg=C["bg"]):
        self.font = tkfont.Font(font=F["small"])
        h = self.font.metrics("linespace") + 8
        super().__init__(master, height=h, width=40, bg=bg, highlightthickness=0, bd=0)
        self.h = h

    def set(self, text: str, colour: str) -> None:
        self.delete("all")
        h = self.h
        self.configure(width=self.font.measure(text) + 20)
        self.create_oval(2, h / 2 - 4, 10, h / 2 + 4, fill=colour, outline="")
        self.create_text(18, h / 2, text=text, anchor="w", fill=C["fg"], font=self.font)


class LevelMeter(tk.Canvas):
    """Microphone level drawn as waveform bars, the same mark as the logo."""
    PATTERN = (0.36, 0.73, 1.0, 0.64, 0.27, 0.5, 0.86, 0.45)

    def __init__(self, master, accent, bars=24, height=20):
        super().__init__(master, width=bars * 6, height=height, bg=C["card"], highlightthickness=0, bd=0)
        self.bars, self.h, self.accent = bars, height, accent
        self.set(0)

    def set(self, level: float) -> None:
        self.delete("all")
        lit = round(max(0.0, min(1.0, level)) * self.bars)
        colour = self.accent if level < 0.65 else (WARN if level < 0.9 else BAD)
        for i in range(self.bars):
            hgt = max(4, self.PATTERN[i % len(self.PATTERN)] * self.h)
            x, y = i * 6 + 1.5, self.h / 2
            self.create_line(x, y - hgt / 2, x, y + hgt / 2, width=3, capstyle="round",
                             fill=colour if i < lit else C["button"])


def _dot_image(colour: str, size: int = 8) -> tk.PhotoImage:
    img = tk.PhotoImage(width=size, height=size)
    c = (size - 1) / 2
    for y in range(size):
        for x in range(size):
            if (x - c) ** 2 + (y - c) ** 2 <= (size / 2) ** 2:
                img.put(colour, (x, y))
    return img


def _logo(master, accent):
    cv = tk.Canvas(master, width=36, height=36, bg=C["bg"], highlightthickness=0, bd=0)
    _round_rect(cv, 0, 0, 36, 36, 10, fill=accent, outline="")
    for x, hgt in ((8, 8), (13, 16), (18, 20), (23, 12), (28, 6)):
        cv.create_line(x, 18 - hgt / 2, x, 18 + hgt / 2, fill=C["ink"], width=3, capstyle="round")
    return cv


def _header(master, accent, subtitle):
    h = ttk.Frame(master, padding=(16, 12, 16, 12))
    h.pack(fill="x")
    _logo(h, accent).pack(side="left")
    t = ttk.Frame(h, padding=(12, 0, 0, 0))
    t.pack(side="left")
    ttk.Label(t, text="SecureVoice", style="Title.TLabel").pack(anchor="w")
    ttk.Label(t, text=subtitle, style="Sub.TLabel").pack(anchor="w")
    pill = Pill(h)
    pill.pack(side="right")
    return pill


def _card(master, title, fill="x", expand=False, pady=(0, 12), padding=(16, 12, 16, 12), padx=16):
    outer = tk.Frame(master, bg=C["card"], highlightthickness=1, highlightbackground=C["border"],
                     highlightcolor=C["border"], bd=0)
    outer.pack(fill=fill, expand=expand, padx=padx, pady=pady)
    inner = ttk.Frame(outer, style="Card.TFrame", padding=padding)
    inner.pack(fill="both", expand=True)
    if title:
        ttk.Label(inner, text=title, style="Section.Card.TLabel").pack(anchor="w", pady=(0, 8))
    return inner


def _tile(master, title, accent):
    f = tk.Frame(master, bg=C["card"], highlightthickness=1, highlightbackground=C["border"], bd=0)
    inner = ttk.Frame(f, style="Card.TFrame", padding=(16, 12))
    inner.pack(fill="both", expand=True)
    ttk.Label(inner, text=title, style="Label.Card.TLabel").pack(anchor="w")
    val = ttk.Label(inner, text="–", style="Value.Card.TLabel")
    val.pack(anchor="w", pady=(4, 0))
    note = ttk.Label(inner, text="", style="Muted.Card.TLabel")
    note.pack(anchor="w")
    return f, val, note


def _listbox(master, height):
    wrap = tk.Frame(master, bg=C["field"])
    lb = tk.Listbox(wrap, height=height, font=F["mono_small"])
    lb.pack(side="left", fill="both", expand=True, padx=(12, 0), pady=8)
    sb = ttk.Scrollbar(wrap, orient="vertical", command=lb.yview)
    sb.pack(side="right", fill="y")
    lb.configure(yscrollcommand=sb.set)
    return wrap, lb


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
    ALERT = ("SECURITY ALERT", "failed", "error", "Error", "refused", "rejected")
    OK = ("Secure session", "verified", "Sent voice", "Received voice", "listening on", "Listening on")

    def __init__(self, root: tk.Tk):
        self.root = root
        self.q: "queue.Queue" = queue.Queue()
        root.configure(bg=C["bg"])
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

    def _make_log(self, parent, height=8):
        log = _ScrolledText(parent, height=height, state="disabled", font=F["mono_small"], wrap="word")
        log.tag_configure("ts", foreground=C["muted"])
        log.tag_configure("alert", foreground=BAD)
        log.tag_configure("ok", foreground=GOOD)
        log.tag_configure("warn", foreground=WARN)
        log.tag_configure("dim", foreground=C["muted"])
        return log

    def _append(self, widget, text):
        if any(k in text for k in self.ALERT):
            tag = "alert"
        elif "WARNING" in text or "TEST:" in text:
            tag = "warn"
        elif any(k in text for k in self.OK):
            tag = "ok"
        elif text.startswith("  ") or "DATA seq=" in text:
            tag = "dim"
        else:
            tag = ""
        widget.configure(state="normal")
        widget.insert("end", time.strftime("%H:%M:%S  "), ("ts",))
        widget.insert("end", text + "\n", (tag,) if tag else ())
        widget.see("end")
        widget.configure(state="disabled")


# ---------------------------------------------------------------------------
# Peer (source / destination)
# ---------------------------------------------------------------------------
class PeerApp(_QueuedApp):
    PORTS = {"listen": str(DEFAULT_PORT + 1), "connect": str(DEFAULT_PORT)}

    def __init__(self, root: tk.Tk):
        super().__init__(root)
        root.title("SecureVoice – Peer")
        self.k = _accent_styles(root, "peer")
        self.accent = ACCENTS["peer"]
        self.peer = None
        self.recorder = audio.Recorder()
        self.rec_start = None
        self.received = []  # list[VoiceMessage]
        os.makedirs("received", exist_ok=True)
        self._build()

    # ---------- layout ----------
    def _build(self):
        k = self.k
        self.pill = _header(self.root, self.accent, f"Peer · encrypted voice messages · this laptop {local_ip()}")
        self.pill.set("Not connected", MUTED)

        conn = _card(self.root, "Connection")
        g = ttk.Frame(conn, style="Card.TFrame")
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)
        self.name = tk.StringVar(value=socket.gethostname().split(".")[0])
        self.role = tk.StringVar(value="listen")
        self.host = tk.StringVar(value="127.0.0.1")
        self.port = tk.StringVar(value=self.PORTS["listen"])
        self.passphrase = tk.StringVar()
        self.show_pass = tk.BooleanVar(value=False)

        def label(text, r, c=0):
            ttk.Label(g, text=text, style="Label.Card.TLabel").grid(row=r, column=c, sticky="w", padx=(0, 12), pady=4)

        label("Role", 0)
        seg = ttk.Frame(g, style="Card.TFrame")
        seg.grid(row=0, column=1, columnspan=2, sticky="w", pady=4)
        for text, value in (("Listen · destination", "listen"), ("Connect · source", "connect")):
            ttk.Radiobutton(seg, text=text, value=value, variable=self.role, style=f"{k}.Seg.Toolbutton",
                            command=self._role_changed).pack(side="left")
        self.start_btn = ttk.Button(g, text="Start", style=f"{k}.Accent.TButton", command=self.start)
        self.start_btn.grid(row=0, column=3, sticky="e", pady=4)
        label("Name", 1)
        ttk.Entry(g, textvariable=self.name, style=f"{k}.TEntry", width=22).grid(row=1, column=1, sticky="w")
        label("Port", 1, 2)
        ttk.Entry(g, textvariable=self.port, style=f"{k}.TEntry", width=8).grid(row=1, column=3, sticky="w")
        label("Peer / relay IP", 2)
        self.host_entry = ttk.Entry(g, textvariable=self.host, style=f"{k}.TEntry", width=22)
        self.host_entry.grid(row=2, column=1, sticky="w")
        self.host_hint = ttk.Label(g, text="", style="Muted.Card.TLabel")
        self.host_hint.grid(row=2, column=2, columnspan=2, sticky="w")
        label("Shared PIN", 3)
        self.pass_entry = ttk.Entry(g, textvariable=self.passphrase, style=f"{k}.TEntry", show="•")
        self.pass_entry.grid(row=3, column=1, columnspan=2, sticky="we")
        ttk.Checkbutton(g, text="Show", variable=self.show_pass, style=f"{k}.TCheckbutton",
                        command=lambda: self.pass_entry.configure(show="" if self.show_pass.get() else "•")
                        ).grid(row=3, column=3, sticky="w", padx=(12, 0))
        self._role_changed()

        pipe = _card(self.root, "Encryption")
        ttk.Label(pipe, text="Shared PIN → PBKDF2 key stretching → AES-256-GCM (one authenticated cipher)",
                  style="Muted.Card.TLabel").pack(anchor="w", pady=(0, 8))
        row = ttk.Frame(pipe, style="Card.TFrame")
        row.pack(fill="x")
        self.chips = []
        chip = tk.Frame(row, bg=C["field"], highlightthickness=1, highlightbackground=C["border"], bd=0)
        chip.pack(side="left", fill="x", expand=True)
        head = tk.Frame(chip, bg=C["field"])
        head.pack(fill="x", padx=12, pady=(8, 0))
        n = tk.Label(head, text="AES", bg=C["field"], fg=C["muted"], font=F["small"])
        n.pack(side="left")
        tk.Label(head, text="AES-256-GCM", bg=C["field"], fg=C["secondary"],
                 font=F["small"]).pack(side="left", padx=(8, 0))
        v = tk.Label(chip, text="Waiting for a session", bg=C["field"], fg=C["muted"],
                     font=F["mono_small"], anchor="w")
        v.pack(fill="x", padx=12, pady=(4, 8))
        self.chips.append((chip, n, v))

        voice = _card(self.root, "Voice messages")
        vr = ttk.Frame(voice, style="Card.TFrame")
        vr.pack(fill="x")
        self.rec_btn = ttk.Button(vr, text="●  Record", style=f"{k}.Accent.TButton", width=14,
                                  command=self.toggle_record, state="disabled")
        self.rec_btn.pack(side="left")
        self.timer = ttk.Label(vr, text="00:00", style="Timer.Card.TLabel")
        self.timer.pack(side="left", padx=(16, 12))
        self.meter = LevelMeter(vr, self.accent)
        self.meter.pack(side="left")
        self.file_btn = ttk.Button(vr, text="Send WAV file…", command=self.send_file, state="disabled")
        self.file_btn.pack(side="right")

        ttk.Label(voice, text="Received", style="Label.Card.TLabel").pack(anchor="w", pady=(16, 8))
        ir = ttk.Frame(voice, style="Card.TFrame")
        ir.pack(fill="both", expand=True)
        wrap, self.inbox = _listbox(ir, 3)
        wrap.pack(side="left", fill="both", expand=True)
        self.inbox.bind("<Double-Button-1>", lambda e: self.play_selected())
        btns = ttk.Frame(ir, style="Card.TFrame")
        btns.pack(side="left", padx=(12, 0), anchor="n")
        ttk.Button(btns, text="▶  Play", command=self.play_selected).pack(fill="x")
        ttk.Button(btns, text="■  Stop", command=audio.stop_playback).pack(fill="x", pady=(8, 0))

        act = _card(self.root, "Activity", fill="both", expand=True, pady=(0, 16))
        self.log = self._make_log(act, height=3)
        self.log.pack(fill="both", expand=True)
        self.root.protocol("WM_DELETE_WINDOW", self.quit)

    def _role_changed(self):
        role = self.role.get()
        other = "connect" if role == "listen" else "listen"
        if self.port.get() == self.PORTS[other]:          # follow the demo's default ports
            self.port.set(self.PORTS[role])
        if role == "listen":
            self.host_entry.configure(state="disabled")
            self.host_hint.configure(text="Not used when listening")
        else:
            self.host_entry.configure(state="normal")
            self.host_hint.configure(text="IP of the relay, or of the other peer")

    def _set_chips(self, lk):
        if lk is None:
            values = ["Waiting for a session"]
        else:
            values = [f"256-bit key · id {hashlib.sha256(lk.aes).hexdigest()[:8].upper()}"]
        for (chip, n, v), text in zip(self.chips, values):
            on = lk is not None
            n.configure(fg=self.accent if on else C["muted"])
            v.configure(text=text, fg=C["fg"] if on else C["muted"])

    def logmsg(self, text):
        self.post(self._append, self.log, text)

    # ---------- connection ----------
    def start(self):
        try:
            port = int(self.port.get())
        except ValueError:
            messagebox.showerror("Port", "Port must be a number")
            return
        passphrase = self.passphrase.get()
        if not passphrase:
            messagebox.showerror("Passphrase", "Enter the shared passphrase first "
                                 "(the same one on both laptops).")
            return
        self.logmsg("The passphrase stays on this laptop – only an HMAC proof of it is exchanged")
        warning = passphrase_warning(passphrase)
        if warning:
            self.logmsg("WARNING: " + warning)
        self.peer = Peer(passphrase, self.name.get() or "peer",
                         on_voice=lambda m: self.post(self._on_voice, m),
                         on_text=lambda s, t: self.logmsg(f"{s}: {t}"),
                         on_log=self.logmsg,
                         on_closed=lambda e: self.post(self._on_closed, e))
        self.start_btn.configure(state="disabled")
        role, host = self.role.get(), self.host.get().strip()   # read Tk values on the GUI thread
        self.pill.set("Waiting for peer…" if role == "listen" else "Connecting…", WARN)

        def run():
            try:
                if role == "listen":
                    self.peer.listen_and_accept(port)
                else:
                    self.peer.connect(host, port)
                self.post(self._on_connected)
            except Exception as e:
                self.logmsg(f"Handshake failed: {e}")
                self.post(self._on_closed, e)
        threading.Thread(target=run, daemon=True).start()

    def _on_connected(self):
        self.pill.set(f"Secure · {self.peer.channel.peer_name}", GOOD)
        self._set_chips(self.peer.channel.layer_keys)
        self.rec_btn.configure(state="normal")
        self.file_btn.configure(state="normal")

    def _on_closed(self, err):
        self.pill.set("Connection failed" if err else "Disconnected", BAD if err else MUTED)
        self._set_chips(None)
        if self.rec_start is not None:
            self.recorder.stop()
            self.rec_start = None
            self.rec_btn.configure(text="●  Record", style=f"{self.k}.Accent.TButton")
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
            self.rec_btn.configure(text="■  Stop & Send", style=f"{self.k}.Danger.TButton")
            self.timer.configure(foreground=BAD)
            self._tick()
        else:
            pcm = self.recorder.stop()
            self.rec_start = None
            self.rec_btn.configure(text="●  Record", style=f"{self.k}.Accent.TButton")
            self.timer.configure(foreground=C["fg"])
            self.meter.set(0)
            self._send(pcm, audio.SAMPLE_RATE, audio.CHANNELS, audio.SAMPLE_WIDTH)

    def _tick(self):
        if self.rec_start is not None:
            s = int(time.time() - self.rec_start)
            self.timer.configure(text=f"{s // 60:02d}:{s % 60:02d}")
            self.meter.set(self.recorder.level)
            self.root.after(80, self._tick)

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
        self.inbox.insert("end", f"  #{m.msg_id:<3} {time.strftime('%H:%M:%S')}   {m.duration:5.1f} s   "
                                 f"from {m.sender}   verified")
        self.inbox.see("end")

    def play_selected(self):
        sel = self.inbox.curselection()
        if sel:
            m = self.received[sel[0]]
            audio.play(m.pcm, m.sample_rate, m.channels)

    def quit(self):
        if self.peer:
            self.peer.close()
        self.root.destroy()


# ---------------------------------------------------------------------------
# Relay (man in the middle)
# ---------------------------------------------------------------------------
MODE_INFO = {
    "observe": "Passive · forwards everything unchanged and measures the ciphertext (noise)",
    "crack": "Passive · brute-forces the shared PIN from the handshake, then decrypts the REAL voice · neither side notices",
    "tamper": "Active · flips one bit in DATA frame #{n} · with a strong key the receiver rejects it (integrity check)",
    "replay": "Active · re-sends an earlier frame at DATA frame #{n} · the receiver rejects it (sequence check)",
    "drop": "Active · deletes DATA frame #{n} · the receiver rejects the message (missing frame)",
    "forge": "Active · detects the sender (either direction), drops the real message, and injects a fake you record live · the receiver accepts it as genuine",
}


class RelayApp(_QueuedApp):
    def __init__(self, root: tk.Tk):
        super().__init__(root)
        root.title("SecureVoice – Man in the middle")
        k = self.k = _accent_styles(root, "relay")
        self.accent = ACCENTS["relay"]
        self.relay = None
        self._entropy_cache = (0, 0.0)
        self.recorder = audio.Recorder()
        self.rec_start = None
        self.fake_pcm_recorded = None
        self.fake_rate_recorded = audio.SAMPLE_RATE
        self._alerted = -1               # index of the last detection announced in the log
        self.pill = _header(root, self.accent, f"Man in the middle · inspection relay · this laptop {local_ip()}")
        self.pill.set("Idle", MUTED)

        cfg = _card(root, "Relay settings")
        g = ttk.Frame(cfg, style="Card.TFrame")
        g.pack(fill="x")
        self.lport = tk.StringVar(value=str(DEFAULT_PORT))
        self.dhost = tk.StringVar(value="127.0.0.1")
        self.dport = tk.StringVar(value=str(DEFAULT_PORT + 1))
        self.mode = tk.StringVar(value="observe")
        self.trigger = tk.StringVar(value="5")
        fields = [("Listen port", self.lport, 0, 0, 8), ("Destination IP", self.dhost, 0, 2, 18),
                  ("Destination port", self.dport, 1, 2, 8), ("Trigger DATA frame #", self.trigger, 1, 0, 8)]
        for text, var, r, c, w in fields:
            ttk.Label(g, text=text, style="Label.Card.TLabel").grid(row=r, column=c, sticky="w", padx=(0, 12), pady=4)
            ttk.Entry(g, textvariable=var, style=f"{k}.TEntry", width=w).grid(row=r, column=c + 1, sticky="w", padx=(0, 24))
        ttk.Label(g, text="Mode", style="Label.Card.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        seg = ttk.Frame(g, style="Card.TFrame")
        seg.grid(row=2, column=1, columnspan=3, sticky="w", pady=4)
        for m in MODES:
            ttk.Radiobutton(seg, text=m, value=m, variable=self.mode, style=f"{k}.Seg.Toolbutton",
                            command=self._mode_changed).pack(side="left")
        self.mode_info = ttk.Label(g, text="", style="Muted.Card.TLabel", wraplength=600)
        self.mode_info.grid(row=3, column=1, columnspan=3, sticky="w")
        self.trigger.trace_add("write", lambda *a: self._mode_changed())
        fake = ttk.Frame(cfg, style="Card.TFrame")
        fake.pack(fill="x", pady=(10, 0))
        ttk.Label(fake, text="Fake recording (forge)", style="Label.Card.TLabel").pack(side="left", padx=(0, 12))
        self.fake_path = tk.StringVar()
        self.fake_entry = ttk.Entry(fake, textvariable=self.fake_path, style=f"{k}.TEntry")
        self.fake_entry.pack(side="left", fill="x", expand=True)
        self.fake_rec_btn = ttk.Button(fake, text="●  Record", width=12, command=self.toggle_fake_record)
        self.fake_rec_btn.pack(side="left", padx=(8, 0))
        self.fake_timer = ttk.Label(fake, text="", style="Muted.Card.TLabel")
        self.fake_timer.pack(side="left", padx=(8, 0))
        self.fake_btn = ttk.Button(fake, text="Browse…", command=self._browse_fake)
        self.fake_btn.pack(side="left", padx=(8, 0))
        foot = ttk.Frame(cfg, style="Card.TFrame")
        foot.pack(fill="x", pady=(12, 0))
        self.btn = ttk.Button(foot, text="Start relay", style=f"{k}.Accent.TButton", command=self.start)
        self.btn.pack(side="right")
        self._mode_changed()

        tiles = ttk.Frame(root, padding=(16, 0, 16, 12))
        tiles.pack(fill="x")
        self.tiles = {}
        for i, (key, title) in enumerate((("frames", "Frames seen"), ("bytes", "Intercepted"),
                                          ("entropy", "Entropy"))):
            f, val, note = _tile(tiles, title, self.accent)
            f.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 12, 0))
            tiles.columnconfigure(i, weight=1, uniform="tile")
            self.tiles[key] = (val, note)
        self.tiles["entropy"][1].configure(text="bits per byte · 8.000 = random")

        heard = _card(root, "Intercepted voice")
        hr = ttk.Frame(heard, style="Card.TFrame")
        hr.pack(fill="both", expand=True)
        wrap, self.heard = _listbox(hr, 3)
        wrap.pack(side="left", fill="both", expand=True)
        self.heard.bind("<Double-Button-1>", lambda e: self.play_intercepted())
        hb = ttk.Frame(hr, style="Card.TFrame")
        hb.pack(side="left", padx=(12, 0), anchor="n")
        ttk.Button(hb, text="▶  Noise", command=self.play_intercepted).pack(fill="x")
        ttk.Button(hb, text="▶  Decrypted", command=self.play_recovered).pack(fill="x", pady=(8, 0))
        ttk.Button(hb, text="■  Stop", command=audio.stop_playback).pack(fill="x", pady=(8, 0))
        ttk.Button(hb, text="Cryptanalysis lab…", command=lambda: open_lab(self.root)).pack(fill="x", pady=(8, 0))

        act = _card(root, "Activity", fill="both", expand=True, pady=(0, 16))
        self.log = self._make_log(act, height=4)
        self.log.pack(fill="both", expand=True)
        self._refresh()

    def _browse_fake(self):
        p = filedialog.askopenfilename(filetypes=[("WAV audio", "*.wav")], initialdir="received")
        if p:
            self.fake_path.set(p)
            self.fake_pcm_recorded = None          # a chosen file overrides any recording

    def _live_forge(self):
        r = self.relay
        return bool(r and self.mode.get() == "forge"
                    and getattr(r, "source_transmitting", False))

    def toggle_fake_record(self):
        if self.rec_start is None:
            try:
                self.recorder.start()
            except Exception as e:
                messagebox.showerror("Microphone", str(e))
                return
            self.rec_start = time.time()
            self.fake_rec_btn.configure(text="■  Stop & inject" if self._live_forge() else "■  Stop")
            self.fake_timer.configure(foreground=BAD)
            self._fake_tick()
        else:
            pcm = self.recorder.stop()
            self.rec_start = None
            self.fake_rec_btn.configure(text="●  Record")
            secs = len(pcm) / (audio.SAMPLE_RATE * audio.SAMPLE_WIDTH)
            if self._live_forge():                        # source is transmitting: inject now
                r = self.relay
                self.post(self._append, self.log, f"[relay] injecting your {secs:.1f}s fake message now…")
                threading.Thread(target=lambda: r.inject_fake(pcm, audio.SAMPLE_RATE), daemon=True).start()
                self.fake_timer.configure(text=f"{secs:.1f}s injected", foreground=C["muted"])
            else:                                         # otherwise stage it for later
                self.fake_pcm_recorded = pcm
                self.fake_rate_recorded = audio.SAMPLE_RATE
                self.fake_path.set(f"[recorded {secs:.1f}s from mic]")
                self.fake_timer.configure(text=f"{secs:.1f}s ready", foreground=C["muted"])

    def _fake_tick(self):
        if self.rec_start is not None:
            s = int(time.time() - self.rec_start)
            self.fake_timer.configure(text=f"{s // 60:02d}:{s % 60:02d}")
            self.root.after(100, self._fake_tick)

    def _mode_changed(self):
        mode = self.mode.get()
        text = MODE_INFO.get(mode, "").format(n=self.trigger.get() or "?")
        self.mode_info.configure(text=text, foreground=C["muted"] if mode == "observe" else WARN)
        state = "normal" if mode == "forge" else "disabled"
        for w in (self.fake_entry, self.fake_btn, self.fake_rec_btn):
            w.configure(state=state)

    def _refresh(self):
        r = self.relay
        if r:
            items = list(r.intercepted)
            if self.heard.size() != len(items) or (items and self._last_label != items[-1].label()):
                sel = self.heard.curselection()
                self.heard.delete(0, "end")
                for m in items:
                    self.heard.insert("end", "  " + m.label())
                for i in sel:
                    self.heard.selection_set(i)
                self._last_label = items[-1].label() if items else ""
            frames = sum(m.frames for m in items)
            size = sum(len(m.data) for m in items)
            self.tiles["frames"][0].configure(text=f"{frames:,}")
            self.tiles["frames"][1].configure(text=f"{len(items)} voice message" + ("" if len(items) == 1 else "s"))
            self.tiles["bytes"][0].configure(text=f"{size / 1e6:.2f} MB" if size >= 1e5 else f"{size / 1e3:.1f} KB")
            self.tiles["bytes"][1].configure(text=f"≈ {size / 32000:.0f} s of audio" if size else "nothing yet")
            if items and size != self._entropy_cache[0]:
                sample = bytes(items[-1].data[-400_000:])
                self._entropy_cache = (size, shannon_entropy(sample))
            if items:
                e = self._entropy_cache[1]
                self.tiles["entropy"][0].configure(text=f"{e:.3f}", foreground=GOOD if e > 7.9 else WARN)
            transmitting = getattr(r, "source_transmitting", False)
            detections = getattr(r, "detections", 0)
            if transmitting and detections != self._alerted:
                self._alerted = detections
                self.post(self._append, self.log,
                          "[relay] ⚠ source detected and intercepted — press ●  Record to capture "
                          "your fake, then stop to inject it")
            if getattr(r, "cracking", False):
                pct = int(r.crack_tries * 100 / max(r.crack_total, 1))
                self.pill.set(f"Brute-forcing… {pct}%  ({r.crack_tries:,}/{r.crack_total:,})", WARN)
            elif transmitting:
                self.pill.set("Source sending — record & inject!", BAD)
            elif getattr(r, "injections", 0):
                n = r.injections
                self.pill.set(f"Fake injected ×{n} · PIN {r.cracked_pin}", WARN)
            elif r.cracked_pin:
                self.pill.set(f"Cracked · PIN {r.cracked_pin}", WARN)
            elif r.done.is_set():
                self.pill.set("Finished", MUTED)
            elif items:
                self.pill.set(f"Intercepting · {self.mode.get()}", WARN)
        self.root.after(700, self._refresh)

    def play_intercepted(self):
        sel = self.heard.curselection()
        if not self.relay or not self.relay.intercepted:
            return
        m = self.relay.intercepted[sel[0] if sel else -1]
        self.post(self._append, self.log,
                  f"[relay] playing intercepted ciphertext as audio ({m.seconds():.1f}s) – "
                  "noise only, the speech cannot be recovered without the session key")
        audio.play(m.as_pcm())

    def play_recovered(self):
        r = self.relay
        if not r:
            return
        self.post(self._append, self.log, "[relay] brute-forcing the PIN and decrypting…")
        if not r.recovered:
            self.post(self.pill.set, "Brute-forcing…", WARN)

        def work():
            recovered = r.recover_all()        # always refresh: full length, picks up new messages
            if not recovered:
                return                         # recover_all() already logged why
            direction, pcm, rate = recovered[-1]   # the most recent complete message
            self.post(self._append, self.log,
                      f"[relay] playing the DECRYPTED real voice ({direction}, "
                      f"{len(pcm) / 2 / rate:.1f}s) – recovered with the cracked PIN {r.cracked_pin}")
            audio.play(pcm, rate)
        threading.Thread(target=work, daemon=True).start()

    def start(self):
        mode = self.mode.get()
        fake_pcm, fake_rate = None, 16000
        if mode == "forge":
            if self.rec_start is not None:
                messagebox.showerror("Fake recording", "Finish the recording first (press ■ Stop).")
                return
            self._alerted = -1
            path = self.fake_path.get()
            if self.fake_pcm_recorded:                     # a fake was prepared earlier
                fake_pcm, fake_rate = self.fake_pcm_recorded, self.fake_rate_recorded
            elif path and not path.startswith("["):        # a WAV file was chosen
                try:
                    fake_pcm, fake_rate, _, _ = audio.load_wav(path)
                except Exception as e:
                    messagebox.showerror("Fake recording", f"Cannot load that WAV:\n{e}")
                    return
            # else: no fake yet — record it live when the source starts transmitting
        try:
            relay = InspectionRelay(int(self.lport.get()), self.dhost.get().strip(),
                                    int(self.dport.get()), mode, int(self.trigger.get()),
                                    on_log=lambda t: self.post(self._append, self.log, t),
                                    fake_pcm=fake_pcm, fake_rate=fake_rate)
        except ValueError as e:
            messagebox.showerror("Settings", str(e))
            return
        self.relay, self._last_label = relay, ""
        self.btn.configure(state="disabled")
        self.pill.set(f"Listening on :{self.lport.get()}", WARN)

        def run():
            try:
                relay.serve_once()
            except Exception as e:
                self.post(self._append, self.log, f"[relay] error: {e}")
                self.post(self.pill.set, "Error", BAD)
            self.post(lambda: self.btn.configure(state="normal"))
        threading.Thread(target=run, daemon=True).start()


# ---------------------------------------------------------------------------
# Cryptanalysis lab
# ---------------------------------------------------------------------------
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
        root.title("SecureVoice – Cryptanalysis lab")
        k = self.k = _accent_styles(root, "lab")
        self.accent = ACCENTS["lab"]
        self.results, self.pcm, self.rate, self.ch, self.known_secs = [], b"", 16000, 1, 0.5
        self.pill = _header(root, self.accent, "Cryptanalysis lab · offline, on your own recording")
        self.pill.set("Ready", MUTED)

        cfg = _card(root, "Experiment")
        g = ttk.Frame(cfg, style="Card.TFrame")
        g.pack(fill="x")
        g.columnconfigure(1, weight=1)
        self.path = tk.StringVar(value=self._latest_recording())
        self.secs = tk.StringVar(value="20")
        self.known = tk.StringVar(value="0.5")
        ttk.Label(g, text="Recording (WAV)", style="Label.Card.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 12), pady=4)
        ttk.Entry(g, textvariable=self.path, style=f"{k}.TEntry").grid(row=0, column=1, columnspan=3, sticky="we")
        ttk.Button(g, text="Browse…", command=self._browse).grid(row=0, column=4, padx=(8, 0))
        ttk.Label(g, text="Use first (s)", style="Label.Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(g, textvariable=self.secs, style=f"{k}.TEntry", width=6).grid(row=1, column=1, sticky="w")
        ttk.Label(g, text="Attacker knows first (s)", style="Label.Card.TLabel").grid(row=1, column=2, sticky="e", padx=(0, 12))
        ttk.Entry(g, textvariable=self.known, style=f"{k}.TEntry", width=6).grid(row=1, column=3, sticky="w")
        self.run_btn = ttk.Button(g, text="Run all attacks", style=f"{k}.Accent.TButton", command=self.run)
        self.run_btn.grid(row=1, column=4, padx=(8, 0))
        self.status = ttk.Label(cfg, text="Keys are random for each run · nothing is sent on the network",
                                style="Muted.Card.TLabel")
        self.status.pack(anchor="w", pady=(8, 0))

        body = ttk.Frame(root, padding=(16, 0, 16, 16))
        body.pack(fill="both", expand=True)
        left = ttk.Frame(body)
        left.pack(side="left", fill="both", expand=True)
        right = ttk.Frame(body)
        right.pack(side="left", fill="both", padx=(12, 0))

        res = _card(left, "Results", fill="both", expand=True, pady=0, padx=0)
        cols = ("layers", "attack", "result", "recovered", "time")
        self.tree = ttk.Treeview(res, columns=cols, show="tree headings", height=9, selectmode="browse")
        self._dots = {"broken": _dot_image(BAD), "safe": _dot_image(GOOD)}
        self.tree.heading("#0", text="")
        self.tree.column("#0", width=28, minwidth=28, stretch=False)
        for c, title, w in zip(cols, ("Layers", "Attack", "Result", "Recovered", "Time"),
                               (240, 132, 92, 104, 64)):
            self.tree.heading(c, text=title, anchor="w")
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._show_detail())
        btns = ttk.Frame(res, style="Card.TFrame")
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="▶  Play original", command=self.play_original).pack(side="left")
        ttk.Button(btns, text="▶  Play attacker's result", command=self.play_result).pack(side="left", padx=8)
        ttk.Button(btns, text="■  Stop", command=audio.stop_playback).pack(side="left")

        self.tiles = {}
        for key, title in (("classic", "Without AES"), ("aes", "With AES")):
            f, val, note = _tile(right, title, self.accent)
            f.pack(fill="x", pady=(0, 12))
            self.tiles[key] = (val, note)
        det = _card(right, "Details", fill="both", expand=True, pady=0, padx=0)
        self.detail = _ScrolledText(det, width=42, height=6, wrap="word", font=F["small"], state="disabled",
                                    spacing1=2, spacing3=2)
        self.detail.tag_configure("h", foreground=C["fg"], font=F["base"])
        self.detail.pack(fill="both", expand=True)

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
        for val, note in self.tiles.values():
            val.configure(text="–", foreground=C["fg"])
            note.configure(text="")
        self.run_btn.configure(state="disabled")
        self.pill.set("Running…", WARN)
        self.status.configure(text="Running… the two pattern searches take a few seconds each")
        known_bytes = int(rate * known) * ch * 2

        def work():
            try:
                analysis.run_attacks(self.pcm, known_bytes, on_result=lambda r: self.post(self._add, r))
                self.post(self.status.configure, {"text": "Done · select a row for details, then play the result"})
                self.post(self.pill.set, "Done", GOOD)
            except Exception as e:
                self.post(self.status.configure, {"text": f"Error: {e}"})
                self.post(self.pill.set, "Error", BAD)
            self.post(lambda: self.run_btn.configure(state="normal"))
        threading.Thread(target=work, daemon=True).start()

    def _add(self, r):
        self.results.append(r)
        self.tree.insert("", "end", iid=str(len(self.results) - 1),
                         image=self._dots["broken" if r["success"] else "safe"],
                         values=(r["case"], r["attack"], "Broken" if r["success"] else "Resisted",
                                 f"{r['recovered']:.0%}", f"{r['secs']:.2f} s"))
        for key, group in (("classic", [x for x in self.results if x["layers"] < 3]),
                           ("aes", [x for x in self.results if x["layers"] == 3])):
            if group:
                broken = sum(x["success"] for x in group)
                val, note = self.tiles[key]
                val.configure(text=f"{broken} of {len(group)} broken", foreground=BAD if broken else GOOD)
                note.configure(text="voice recovered by the attacker" if broken else "attacker hears only noise")

    def _selected(self):
        sel = self.tree.selection()
        return self.results[int(sel[0])] if sel else None

    def _show_detail(self):
        r = self._selected()
        if not r:
            return
        equiv = (r["success"] and r["key"].split(" cols")[0] != r["real_key"].split(" cols")[0])
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("end", f"{r['attack']} attack on {r['case']}\n\n", ("h",))
        self.detail.insert("end", f"Attacker's position: {ATTACK_INFO[r['attack']].format(known=self.known_secs)}\n\n"
                                  f"What happened: {r['detail']}.\n\n"
                                  f"Key the attacker found: {r['key']}\n"
                                  f"Real key:               {r['real_key']}\n"
                           + ("(A different but equivalent Affine key gives the same audio with inverted polarity.)\n"
                              if equiv else "")
                           + f"\nVoice recovered: {r['recovered']:.0%} (correlation with the original).")
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


def run_peer():
    root = make_root()
    PeerApp(root)
    root.mainloop()


def run_relay():
    root = make_root()
    RelayApp(root)
    root.mainloop()
