import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import cv2
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import hashlib
import struct
import random
import string


# ─── Crypto helpers ────────────────────────────────────────────────────────────

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt(message: str, password: str) -> bytes:
    key = derive_key(password)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv + ct

def decrypt(data: bytes, password: str) -> str:
    key = derive_key(password)
    iv, ct = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plain = unpadder.update(padded) + unpadder.finalize()
    return plain.decode()

def garbage_text(length=80) -> str:
    chars = string.printable[:72]
    return "".join(random.choice(chars) for _ in range(length))


# ─── Steganography core ────────────────────────────────────────────────────────

MAGIC = b'\xDE\xAD\xBE\xEF'

def embed_message(video_path: str, message: str, password: str,
                  output_path: str, progress_cb=None):
    encrypted = encrypt(message, password)
    payload = MAGIC + struct.pack('>I', len(encrypted)) + encrypted

    out_path = os.path.splitext(output_path)[0] + ".mp4"
    with open(video_path, 'rb') as src:
        video_bytes = src.read()
    if progress_cb:
        progress_cb(40)

    TRAILER = b'\x00\x00STEGOPAYLOAD\x00\x00'
    with open(out_path, 'wb') as dst:
        dst.write(video_bytes)
        dst.write(TRAILER)
        dst.write(payload)
        dst.write(struct.pack('>I', len(payload)))
        dst.write(TRAILER)
    if progress_cb:
        progress_cb(100)
    return out_path

def extract_message(video_path: str, password: str, progress_cb=None) -> str:
    TRAILER = b'\x00\x00STEGOPAYLOAD\x00\x00'
    if progress_cb:
        progress_cb(20)

    with open(video_path, 'rb') as f:
        data = f.read()

    if progress_cb:
        progress_cb(60)

    idx = data.rfind(TRAILER)
    if idx < 0:
        return garbage_text(120)

    first = data.find(TRAILER)
    if first < 0 or first == idx:
        return garbage_text(120)

    payload = data[first + len(TRAILER): idx]

    if progress_cb:
        progress_cb(80)

    if not payload.startswith(MAGIC):
        return garbage_text(120)

    if len(payload) < 8:
        return garbage_text(120)

    enc_len = struct.unpack('>I', payload[4:8])[0]
    encrypted = payload[8: 8 + enc_len]

    if len(encrypted) != enc_len:
        return garbage_text(120)

    if progress_cb:
        progress_cb(100)

    try:
        return decrypt(encrypted, password)
    except Exception:
        return garbage_text(120)


# ─── GUI ───────────────────────────────────────────────────────────────────────

DARK_BG      = "#0f1117"
SURFACE      = "#1a1d27"
SURFACE2     = "#232736"
ACCENT       = "#6c63ff"
ACCENT2      = "#a78bfa"
TEXT_PRIMARY = "#f0f0f5"
TEXT_MUTED   = "#8b8fa8"
SUCCESS      = "#22c55e"
ERROR        = "#ef4444"
WARNING      = "#f59e0b"
BORDER       = "#2e3148"


class VideoStegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VideoSteg — Steganography & Encryption")
        self.configure(bg=DARK_BG)
        self.geometry("820x680")
        self.resizable(True, True)
        self.minsize(700, 580)

        self._embed_video   = tk.StringVar()
        self._embed_key     = tk.StringVar()
        self._extract_video = tk.StringVar()
        self._extract_key   = tk.StringVar()

        self._build_ui()

    def _build_ui(self):
        hdr = tk.Frame(self, bg=DARK_BG)
        hdr.pack(fill="x", padx=24, pady=(20, 0))
        tk.Label(hdr, text="VideoSteg", font=("Helvetica", 22, "bold"),
                 bg=DARK_BG, fg=ACCENT2).pack(side="left")
        tk.Label(hdr, text="AES-256 encryption  |  Video steganography",
                 font=("Helvetica", 11), bg=DARK_BG, fg=TEXT_MUTED).pack(side="left", padx=14)

        tab_bar = tk.Frame(self, bg=DARK_BG)
        tab_bar.pack(fill="x", padx=24, pady=(16, 0))
        self._tab_btns = {}
        for label, key in [("  Embed Message  ", "embed"), ("  Extract Message  ", "extract")]:
            b = tk.Button(tab_bar, text=label, font=("Helvetica", 12),
                          bg=SURFACE2, fg=TEXT_MUTED, relief="flat",
                          activebackground=SURFACE2, cursor="hand2",
                          command=lambda k=key: self._switch_tab(k),
                          padx=10, pady=8, bd=0)
            b.pack(side="left", padx=(0, 4))
            self._tab_btns[key] = b
        tk.Frame(self, bg=ACCENT, height=2).pack(fill="x", padx=24)

        self._panels = {}
        container = tk.Frame(self, bg=DARK_BG)
        container.pack(fill="both", expand=True, padx=24, pady=16)
        self._panels["embed"]   = self._build_embed_panel(container)
        self._panels["extract"] = self._build_extract_panel(container)
        self._switch_tab("embed")

    def _switch_tab(self, key):
        for k, p in self._panels.items():
            p.pack_forget()
        self._panels[key].pack(fill="both", expand=True)
        for k, b in self._tab_btns.items():
            if k == key:
                b.configure(bg=SURFACE, fg=TEXT_PRIMARY)
            else:
                b.configure(bg=SURFACE2, fg=TEXT_MUTED)

    def _build_embed_panel(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        self._section(frame, "1  Select input video").pack(fill="x", pady=(0, 6))
        self._path_entry(frame, self._embed_video,
                         "Source video (.mp4, .avi, ...)",
                         lambda: self._pick_file(self._embed_video,
                             [("Video", "*.mp4 *.avi *.mkv *.mov")])).pack(fill="x", pady=(0, 12))

        self._section(frame, "2  Secret message").pack(fill="x", pady=(0, 6))
        msg_wrap = tk.Frame(frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        msg_wrap.pack(fill="x", pady=(0, 12))
        self._msg_text = tk.Text(msg_wrap, height=5, bg=SURFACE, fg=TEXT_PRIMARY,
                                 insertbackground=ACCENT2, font=("Helvetica", 12),
                                 relief="flat", padx=12, pady=10,
                                 selectbackground=ACCENT)
        self._msg_text.pack(fill="x")

        self._section(frame, "3  Encryption key").pack(fill="x", pady=(0, 6))
        self._key_row(frame, self._embed_key).pack(fill="x", pady=(0, 16))

        self._embed_btn = self._action_btn(frame, "Embed & Export Video", ACCENT, self._do_embed)
        self._embed_btn.pack(fill="x", pady=(0, 12))

        self._embed_progress = self._progress_bar(frame, "P")
        self._embed_progress.pack(fill="x", pady=(0, 8))
        self._embed_status = tk.Label(frame, text="", font=("Helvetica", 11),
                                      bg=DARK_BG, fg=TEXT_MUTED)
        self._embed_status.pack(anchor="w")
        return frame

    def _build_extract_panel(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        self._section(frame, "1  Select encoded video").pack(fill="x", pady=(0, 6))
        self._path_entry(frame, self._extract_video,
                         "Encoded video file",
                         lambda: self._pick_file(self._extract_video,
                             [("Video", "*.mp4 *.avi *.mkv *.mov")])).pack(fill="x", pady=(0, 12))

        self._section(frame, "2  Decryption key").pack(fill="x", pady=(0, 6))
        self._key_row(frame, self._extract_key).pack(fill="x", pady=(0, 16))

        self._extract_btn = self._action_btn(frame, "Extract & Decrypt Message",
                                             "#059669", self._do_extract)
        self._extract_btn.pack(fill="x", pady=(0, 12))

        self._extract_progress = self._progress_bar(frame, "E")
        self._extract_progress.pack(fill="x", pady=(0, 10))

        self._section(frame, "Extracted message").pack(fill="x", pady=(0, 6))
        result_wrap = tk.Frame(frame, bg=SURFACE, highlightbackground=BORDER, highlightthickness=1)
        result_wrap.pack(fill="both", expand=True)
        self._result_text = tk.Text(result_wrap, height=8, bg=SURFACE,
                                    fg=TEXT_PRIMARY, insertbackground=ACCENT2,
                                    font=("Helvetica", 12), relief="flat",
                                    padx=12, pady=10, state="disabled",
                                    selectbackground=ACCENT)
        self._result_text.pack(fill="both", expand=True)

        self._extract_status = tk.Label(frame, text="", font=("Helvetica", 11),
                                        bg=DARK_BG, fg=TEXT_MUTED)
        self._extract_status.pack(anchor="w", pady=(6, 0))
        return frame

    def _section(self, parent, text):
        return tk.Label(parent, text=text, font=("Helvetica", 12, "bold"),
                        bg=DARK_BG, fg=ACCENT2)

    def _path_entry(self, parent, var, placeholder, cmd):
        row = tk.Frame(parent, bg=DARK_BG)
        entry = tk.Entry(row, textvariable=var, font=("Helvetica", 12),
                         bg=SURFACE, fg=TEXT_PRIMARY, insertbackground=ACCENT2,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=ACCENT)
        entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)
        self._placeholder(entry, placeholder, var)
        btn = tk.Button(row, text="Browse", font=("Helvetica", 11),
                        bg=SURFACE2, fg=ACCENT2, relief="flat", cursor="hand2",
                        activebackground=ACCENT, activeforeground="white",
                        command=cmd, padx=14, pady=8)
        btn.pack(side="right", padx=(8, 0))
        return row

    def _placeholder(self, entry, text, var):
        if not var.get():
            entry.insert(0, text)
            entry.configure(fg=TEXT_MUTED)
        def on_focus_in(e):
            if entry.get() == text:
                entry.delete(0, "end")
                entry.configure(fg=TEXT_PRIMARY)
        def on_focus_out(e):
            if not entry.get():
                entry.insert(0, text)
                entry.configure(fg=TEXT_MUTED)
        entry.bind("<FocusIn>", on_focus_in)
        entry.bind("<FocusOut>", on_focus_out)

    def _key_row(self, parent, var):
        row = tk.Frame(parent, bg=DARK_BG)
        tk.Label(row, text="🔑", font=("Helvetica", 14),
                 bg=DARK_BG, fg=WARNING).pack(side="left", padx=(0, 8))
        entry = tk.Entry(row, textvariable=var, font=("Helvetica", 13),
                         bg=SURFACE, fg=TEXT_PRIMARY, insertbackground=ACCENT2,
                         relief="flat", bd=0, highlightthickness=1,
                         highlightbackground=BORDER, highlightcolor=ACCENT,
                         show="•")
        entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=10)
        show = [False]
        def toggle():
            show[0] = not show[0]
            entry.configure(show="" if show[0] else "•")
            eye_btn.configure(text="🙈" if show[0] else "👁")
        eye_btn = tk.Button(row, text="👁", font=("Helvetica", 13),
                            bg=DARK_BG, fg=TEXT_MUTED, relief="flat",
                            cursor="hand2", command=toggle, bd=0)
        eye_btn.pack(side="right", padx=(6, 0))
        return row

    def _action_btn(self, parent, text, color, cmd):
        return tk.Button(parent, text=text, font=("Helvetica", 13, "bold"),
                         bg=color, fg="white", relief="flat", cursor="hand2",
                         activebackground=ACCENT2, activeforeground="white",
                         command=cmd, pady=12)

    def _progress_bar(self, parent, tag):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(f"{tag}.Horizontal.TProgressbar",
                        troughcolor=SURFACE2, background=ACCENT,
                        borderwidth=0, lightcolor=ACCENT, darkcolor=ACCENT)
        return ttk.Progressbar(parent, style=f"{tag}.Horizontal.TProgressbar",
                               length=200, mode="determinate", maximum=100)

    def _pick_file(self, var, types):
        path = filedialog.askopenfilename(filetypes=types)
        if path:
            var.set(path)

    def _do_embed(self):
        video   = self._embed_video.get().strip()
        key     = self._embed_key.get().strip()
        message = self._msg_text.get("1.0", "end").strip()

        if not video or not os.path.isfile(video):
            return self._flash(self._embed_status, "Please select a valid input video.", ERROR)
        if not key:
            return self._flash(self._embed_status, "Please enter an encryption key.", ERROR)
        if not message:
            return self._flash(self._embed_status, "Please enter a secret message.", ERROR)

        base, _ = os.path.splitext(video)
        output  = base + "_stego.mp4"

        self._embed_btn.configure(state="disabled", text="Processing…")
        self._embed_progress["value"] = 0

        def run():
            try:
                embed_message(video, message, key, output,
                              lambda p: self._embed_progress.configure(value=p))
                self.after(0, lambda: self._embed_done(output))
            except Exception as ex:
                err = str(ex)
                self.after(0, lambda: self._embed_error(err))

        threading.Thread(target=run, daemon=True).start()

    def _embed_done(self, path):
        self._embed_btn.configure(state="normal", text="Embed & Export Video")
        self._embed_progress["value"] = 100
        self._flash(self._embed_status, f"✓  Saved as: {os.path.basename(path)}", SUCCESS)

    def _embed_error(self, msg):
        self._embed_btn.configure(state="normal", text="Embed & Export Video")
        self._flash(self._embed_status, f"✗  {msg}", ERROR)

    def _do_extract(self):
        video = self._extract_video.get().strip()
        key   = self._extract_key.get().strip()

        if not video or not os.path.isfile(video):
            return self._flash(self._extract_status, "Please select a valid video.", ERROR)
        if not key:
            return self._flash(self._extract_status, "Please enter a decryption key.", ERROR)

        self._extract_btn.configure(state="disabled", text="Processing…")
        self._extract_progress["value"] = 0
        self._set_result("", TEXT_MUTED)

        def run():
            try:
                result = extract_message(video, key,
                                         lambda p: self._extract_progress.configure(value=p))
                self.after(0, lambda: self._extract_done(result))
            except Exception as ex:
                err = str(ex)
                self.after(0, lambda: self._extract_error(err))

        threading.Thread(target=run, daemon=True).start()

    def _extract_done(self, result):
        self._extract_btn.configure(state="normal", text="Extract & Decrypt Message")
        self._extract_progress["value"] = 100
        self._set_result(result, TEXT_PRIMARY)
        self._flash(self._extract_status, "✓  Message extracted successfully.", SUCCESS)

    def _extract_error(self, msg):
        self._extract_btn.configure(state="normal", text="Extract & Decrypt Message")
        self._flash(self._extract_status, f"✗  {msg}", ERROR)

    def _set_result(self, text, color):
        self._result_text.configure(state="normal", fg=color)
        self._result_text.delete("1.0", "end")
        self._result_text.insert("end", text)
        self._result_text.configure(state="disabled")

    def _flash(self, label, msg, color):
        label.configure(text=msg, fg=color)


def main():
    app = VideoStegoApp()
    app.mainloop()

if __name__ == "__main__":
    main()
