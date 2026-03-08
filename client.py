"""
client.py — SecureTransfer Client
===================================
Tkinter GUI for end-to-end encrypted file transfer.
  - Register / Login with any username
  - Send files encrypted AES-256-CBC + RSA-2048 key wrap
  - Receive and decrypt incoming files + SHA-256 integrity check
  - Attack Monitor tab shows live DoS / Replay / MITM stats
  - Reconnect button if connection is lost

Fixes applied:
  [1] Enter key no longer bleeds into buttons after connect starts
  [2] Attack Monitor works — stats_request bypasses replay check
  [3] Reconnect after logout works — shows Reconnect button, re-opens auth
  [4] Attack Monitor auto-refreshes every 5 seconds when on that tab
"""

import socket
import threading
import json
import os
import time
import struct
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from crypto_utils import (
    generate_rsa_keypair, serialize_public_key, load_public_key,
    hybrid_encrypt_file, hybrid_decrypt_file,
    hash_password, verify_file_integrity, generate_nonce
)

SERVER_HOST  = "127.0.0.1"
SERVER_PORT  = 65433
DOWNLOAD_DIR = "client_downloads"
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


# ── Socket helpers ─────────────────────────────────────────────────────────────

def send_packet(sock, data: dict):
    raw = json.dumps(data).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def recv_packet(sock) -> dict:
    header = _recv_exactly(sock, 4)
    if not header:
        raise ConnectionError("Disconnected")
    length = struct.unpack("!I", header)[0]
    raw    = _recv_exactly(sock, length)
    return json.loads(raw.decode("utf-8"))


def _recv_exactly(sock, n) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ══════════════════════════════════════════════════════════════════════════════
# AUTH WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class AuthWindow:
    """Login / Register screen."""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SecureTransfer — Login")
        self.root.geometry("460x560")
        self.root.resizable(False, False)
        self.root.configure(bg="#F0F4F8")
        self._mode      = "login"
        self._busy      = False   # prevents Enter-key bleed
        self._build_ui()

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg="#1F3864", height=90)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="SecureTransfer",
                 font=("Arial", 22, "bold"), fg="white",
                 bg="#1F3864").pack(pady=(16, 2))
        tk.Label(hdr, text="RSA-2048 + AES-256 Encrypted File Transfer",
                 font=("Arial", 9), fg="#90CAF9", bg="#1F3864").pack()

        # Tab row
        tabs = tk.Frame(self.root, bg="#D0DCF0")
        tabs.pack(fill="x")
        self._login_btn = tk.Button(
            tabs, text="Login to Existing Account", width=22,
            command=lambda: self._switch("login"),
            relief="flat", bg="#2E75B6", fg="white",
            font=("Arial", 10, "bold"), pady=10, cursor="hand2")
        self._reg_btn = tk.Button(
            tabs, text="Create New Account", width=22,
            command=lambda: self._switch("register"),
            relief="flat", bg="#D0DCF0", fg="#444",
            font=("Arial", 10), pady=10, cursor="hand2")
        self._login_btn.pack(side="left", fill="x", expand=True)
        self._reg_btn.pack(side="left", fill="x", expand=True)

        # Hint bar
        hint_bar = tk.Frame(self.root, bg="#EAF2FF")
        hint_bar.pack(fill="x")
        self._hint = tk.Label(
            hint_bar,
            text="  Enter your username and password to log in.",
            font=("Arial", 9), fg="#2E75B6", bg="#EAF2FF",
            anchor="w", pady=6)
        self._hint.pack(fill="x", padx=10)

        # Form
        form = tk.Frame(self.root, bg="#F0F4F8")
        form.pack(fill="both", expand=True, padx=32, pady=16)

        tk.Label(form,
                 text="Username",
                 font=("Arial", 9, "bold"), bg="#F0F4F8", fg="#333").pack(anchor="w")
        self._user_e = tk.Entry(form, font=("Arial", 12), relief="solid", bd=1)
        self._user_e.pack(fill="x", pady=(4, 14), ipady=4)

        tk.Label(form, text="Password",
                 font=("Arial", 9, "bold"), bg="#F0F4F8", fg="#333").pack(anchor="w")
        self._pass_e = tk.Entry(form, font=("Arial", 12),
                                show="•", relief="solid", bd=1)
        self._pass_e.pack(fill="x", pady=(4, 0), ipady=4)

        # Confirm (register only)
        self._conf_frame = tk.Frame(form, bg="#F0F4F8")
        tk.Label(self._conf_frame, text="Confirm Password",
                 font=("Arial", 9, "bold"), bg="#F0F4F8", fg="#333").pack(anchor="w")
        self._conf_e = tk.Entry(self._conf_frame, font=("Arial", 12),
                                show="•", relief="solid", bd=1)
        self._conf_e.pack(fill="x", pady=(4, 0), ipady=4)

        self._status = tk.Label(form, text="", font=("Arial", 9),
                                bg="#F0F4F8", fg="red",
                                wraplength=380, justify="left")

        self._action_btn = tk.Button(
            form, text="Login",
            command=self._do_connect,
            bg="#2E75B6", fg="white",
            font=("Arial", 12, "bold"),
            relief="flat", pady=10, cursor="hand2")

        self._note = tk.Label(
            form,
            text="New user? Click  Create New Account  above.",
            font=("Arial", 8), bg="#F0F4F8", fg="#888")

        self._repack_form()
        self._user_e.focus()
        # Delay Enter binding by 600ms — prevents PowerShell stray Enter on startup
        self.root.after(600, lambda: self.root.bind("<Return>", self._on_enter))

    def _on_enter(self, event):
        """Only fire connect if we are not already connecting."""
        if not self._busy:
            self._do_connect()

    def _repack_form(self):
        self._conf_frame.pack_forget()
        self._status.pack_forget()
        self._action_btn.pack_forget()
        self._note.pack_forget()
        if self._mode == "register":
            self._conf_frame.pack(fill="x", pady=(14, 0))
        self._status.pack(pady=(12, 2), anchor="w")
        self._action_btn.pack(fill="x", pady=(6, 0))
        self._note.pack(pady=(8, 0))

    def _switch(self, mode: str):
        if self._busy:
            return
        self._mode = mode
        if mode == "login":
            self._login_btn.config(bg="#2E75B6", fg="white",
                                   font=("Arial", 10, "bold"))
            self._reg_btn.config(bg="#D0DCF0", fg="#444",
                                 font=("Arial", 10))
            self._action_btn.config(text="Login")
            self._hint.config(
                text="  Enter your username and password to log in.")
            self._note.config(
                text="New user? Click  Create New Account  above.")
            self.root.geometry("460x560")
        else:
            self._reg_btn.config(bg="#2E75B6", fg="white",
                                 font=("Arial", 10, "bold"))
            self._login_btn.config(bg="#D0DCF0", fg="#444",
                                   font=("Arial", 10))
            self._action_btn.config(text="Create Account and Connect")
            self._hint.config(
                text="  Pick any username — it will be created for you.")
            self._note.config(
                text="Already have an account? Click  Login  above.")
            self.root.geometry("460x640")
        self._repack_form()
        self._status.config(text="", fg="red")

    def _do_connect(self):
        if self._busy:
            return
        username = self._user_e.get().strip()
        password = self._pass_e.get()

        if not username or not password:
            self._status.config(
                text="Username and password are required.", fg="red")
            return

        if self._mode == "register":
            if password != self._conf_e.get():
                self._status.config(
                    text="Passwords do not match.", fg="red")
                return

        # Lock everything so Enter/button can't fire again
        self._busy = True
        self._action_btn.config(state="disabled", text="Connecting...")
        self._login_btn.config(state="disabled")
        self._reg_btn.config(state="disabled")
        self._status.config(text="", fg="red")

        threading.Thread(target=self._connect_thread,
                         args=(username, password), daemon=True).start()

    def _connect_thread(self, username: str, password: str):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((SERVER_HOST, SERVER_PORT))
            sock.settimeout(None)   # back to blocking after connect

            send_packet(sock, {
                "type":     self._mode,
                "username": username,
                "password": password
            })
            resp = recv_packet(sock)

            if resp.get("type") == "error":
                self.root.after(0, self._show_error,
                                resp.get("message", "Error"))
                sock.close()
                return

            # Generate RSA key pair for this session
            private_key, public_key = generate_rsa_keypair()
            pem = serialize_public_key(public_key)
            send_packet(sock, {"type": "public_key", "pem": pem})

            # Receive initial user list
            user_list_pkt = recv_packet(sock)
            users = user_list_pkt.get("users", {})

            self.root.after(0, self._open_main,
                            sock, username, private_key, pem, users)

        except ConnectionRefusedError:
            self.root.after(0, self._show_error,
                            "Cannot connect — is the server running?")
        except Exception as e:
            self.root.after(0, self._show_error, str(e))

    def _show_error(self, msg: str):
        self._busy = False
        self._status.config(text=msg, fg="red")
        btn_text = ("Login" if self._mode == "login"
                    else "Create Account and Connect")
        self._action_btn.config(state="normal", text=btn_text)
        self._login_btn.config(state="normal")
        self._reg_btn.config(state="normal")

    def _open_main(self, sock, username, private_key, pem, users):
        self.root.destroy()
        MainWindow(sock, username, private_key, pem, users).run()


# ══════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════

class MainWindow:
    """Main file-transfer hub window."""

    def __init__(self, sock, username, private_key, public_key_pem, users):
        self.sock           = sock
        self.username       = username
        self.private_key    = private_key
        self.public_key_pem = public_key_pem
        self.users          = dict(users)
        self._connected     = True
        self._stats_job     = None   # after() handle for auto-refresh

        self.root = tk.Tk()
        self.root.title(f"SecureTransfer — {username}")
        self.root.geometry("980x700")
        self.root.configure(bg="#F0F4F8")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._build_ui()
        self._start_receive_thread()
        self._log(f"Connected as {username}. RSA-2048 key pair generated.", "success")

    # ── UI ─────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Header
        hdr = tk.Frame(self.root, bg="#1F3864", height=55)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        tk.Label(hdr, text="SecureTransfer",
                 font=("Arial", 16, "bold"), fg="white",
                 bg="#1F3864").pack(side="left", padx=16, pady=12)
        self._conn_lbl = tk.Label(
            hdr, text="Connected  |  AES-256 + RSA-2048",
            font=("Arial", 9), fg="#90CAF9", bg="#1F3864")
        self._conn_lbl.pack(side="right", padx=16)

        # Body
        body = tk.Frame(self.root, bg="#F0F4F8")
        body.pack(fill="both", expand=True)

        # ── Sidebar ────────────────────────────────────────────────────────
        side = tk.Frame(body, bg="#1F3864", width=210)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)

        tk.Label(side, text="Online Users",
                 font=("Arial", 10, "bold"), fg="#90CAF9",
                 bg="#1F3864").pack(pady=(14, 4), padx=10, anchor="w")

        self._ulist = tk.Listbox(
            side, font=("Arial", 10),
            bg="#162A50", fg="white",
            selectbackground="#2E75B6",
            relief="flat", bd=0, activestyle="none")
        self._ulist.pack(fill="both", expand=True, padx=8, pady=4)

        tk.Button(side, text="Send File to Selected",
                  command=self._send_dialog,
                  bg="#2E75B6", fg="white",
                  font=("Arial", 9, "bold"),
                  relief="flat", pady=7).pack(fill="x", padx=8, pady=(4, 2))

        tk.Button(side, text="Refresh Attack Stats",
                  command=self._request_stats,
                  bg="#3a3a5c", fg="#90CAF9",
                  font=("Arial", 9),
                  relief="flat", pady=5).pack(fill="x", padx=8, pady=(2, 4))

        # Reconnect button (hidden until disconnected)
        self._reconnect_btn = tk.Button(
            side, text="Reconnect",
            command=self._reconnect,
            bg="#C0392B", fg="white",
            font=("Arial", 9, "bold"),
            relief="flat", pady=6)
        # Not packed yet — shown only on disconnect

        self._refresh_ulist()

        # ── Notebook ───────────────────────────────────────────────────────
        self._nb = ttk.Notebook(body)
        self._nb.pack(fill="both", expand=True, padx=8, pady=8)
        self._nb.bind("<<NotebookTabChanged>>", self._on_tab_change)

        # Tab 1 — Activity Log
        log_f = tk.Frame(self._nb, bg="#F0F4F8")
        self._nb.add(log_f, text="Activity Log")
        self._log_area = scrolledtext.ScrolledText(
            log_f, font=("Courier", 9),
            bg="#0D1B2A", fg="#A8D8A8",
            relief="flat", bd=0, wrap="word", state="disabled")
        self._log_area.pack(fill="both", expand=True, padx=4, pady=4)
        self._log_area.tag_config("error",   foreground="#FF6B6B")
        self._log_area.tag_config("success", foreground="#4CAF50")
        self._log_area.tag_config("warn",    foreground="#FFA500")
        self._log_area.tag_config("info",    foreground="#64B5F6")

        # Tab 2 — Transfer History
        hist_f = tk.Frame(self._nb, bg="#F0F4F8")
        self._nb.add(hist_f, text="Transfer History")
        cols = ("Time", "Direction", "File", "Peer", "Size", "Status")
        self._hist = ttk.Treeview(hist_f, columns=cols,
                                   show="headings", height=22)
        for c in cols:
            self._hist.heading(c, text=c)
            self._hist.column(c, width=160 if c == "File" else 110)
        sb = ttk.Scrollbar(hist_f, orient="vertical",
                            command=self._hist.yview)
        self._hist.configure(yscrollcommand=sb.set)
        self._hist.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Tab 3 — Attack Monitor
        atk_f = tk.Frame(self._nb, bg="#F0F4F8")
        self._nb.add(atk_f, text="Attack Monitor")

        # Stat counters row
        top = tk.Frame(atk_f, bg="#F0F4F8")
        top.pack(fill="x", padx=10, pady=10)
        self._stat_lbls = {}
        for label, key, col in [
            ("DoS Blocked",   "DoS",    "#C0392B"),
            ("Replay Blocked","Replay", "#D4843E"),
            ("MITM Alerts",   "MITM",   "#7B5EA7"),
            ("Total Events",  "total",  "#1F3864"),
        ]:
            box = tk.Frame(top, bg=col)
            box.pack(side="left", padx=6, fill="x", expand=True)
            tk.Label(box, text=label, font=("Arial", 8),
                     fg="white", bg=col).pack(pady=(8, 2))
            n = tk.Label(box, text="0", font=("Arial", 24, "bold"),
                          fg="white", bg=col)
            n.pack(pady=(0, 8))
            self._stat_lbls[key] = n

        # How it works explanation
        info = tk.Frame(atk_f, bg="#EAF2FF")
        info.pack(fill="x", padx=10, pady=(0, 6))
        tk.Label(
            info,
            text=(
                "How to use: Click  Refresh Attack Stats  in the sidebar to pull live data from the server.\n"
                "DoS = IPs that sent too many requests in 10s.   "
                "Replay = duplicate or stale packets.   "
                "MITM = public key changed between sessions."
            ),
            font=("Arial", 8), fg="#2E75B6", bg="#EAF2FF",
            wraplength=700, justify="left", pady=6
        ).pack(padx=8)

        self._atk_log = scrolledtext.ScrolledText(
            atk_f, font=("Courier", 9),
            bg="#1a0000", fg="#FF9090",
            relief="flat", bd=0, wrap="word",
            state="disabled", height=14)
        self._atk_log.pack(fill="both", expand=True, padx=4, pady=4)

    # ── File transfer ──────────────────────────────────────────────────────────

    def _send_dialog(self):
        if not self._connected:
            messagebox.showerror("Disconnected",
                                 "You are offline. Use Reconnect to log back in.")
            return
        sel = self._ulist.curselection()
        if not sel:
            messagebox.showwarning("No user selected",
                                   "Click a username in the sidebar first.")
            return
        recipient = self._ulist.get(sel[0])
        if recipient == self.username:
            messagebox.showinfo("Info", "You cannot send a file to yourself.")
            return
        filepath = filedialog.askopenfilename(title="Select file to send")
        if not filepath:
            return
        threading.Thread(target=self._send_file,
                         args=(filepath, recipient), daemon=True).start()

    def _send_file(self, filepath: str, recipient: str):
        try:
            filename  = os.path.basename(filepath)
            file_size = os.path.getsize(filepath)
            self._log(f"Encrypting {filename} ({file_size:,} bytes) for {recipient}...")

            with open(filepath, "rb") as f:
                file_bytes = f.read()

            rec_pem = self.users.get(recipient)
            if not rec_pem:
                self._log(f"No public key for {recipient} — are they online?",
                          "error")
                return

            rec_pub = load_public_key(rec_pem)
            payload = hybrid_encrypt_file(file_bytes, rec_pub)

            send_packet(self.sock, {
                "type":          "file_transfer",
                "recipient":     recipient,
                "filename":      filename,
                "ciphertext":    payload["ciphertext"],
                "iv":            payload["iv"],
                "encrypted_key": payload["encrypted_key"],
                "file_hash":     payload["file_hash"],
                "file_size":     file_size,
                "nonce":         generate_nonce(),
                "timestamp":     time.time()
            })

            self.root.after(0, self._add_hist,
                            "Sent", filename, recipient, file_size, "Delivered")
            self._log(
                f"Sent {filename} to {recipient}\n"
                f"  Size      : {file_size:,} bytes\n"
                f"  Encrypted : AES-256-CBC\n"
                f"  Key wrap  : RSA-2048 OAEP\n"
                f"  Hash      : {payload['file_hash'][:32]}...",
                "success")

        except Exception as e:
            self._log(f"Send failed: {e}", "error")

    def _receive_file(self, pkt: dict):
        sender    = pkt.get("sender", "unknown")
        filename  = pkt.get("filename", "file")
        file_hash = pkt.get("file_hash", "")

        self._log(f"Receiving {filename} from {sender}...")
        try:
            file_bytes = hybrid_decrypt_file({
                "ciphertext":    pkt["ciphertext"],
                "iv":            pkt["iv"],
                "encrypted_key": pkt["encrypted_key"],
                "file_hash":     file_hash
            }, self.private_key)

            if not verify_file_integrity(file_bytes, file_hash):
                self._log(f"INTEGRITY FAIL — {filename} may be tampered!", "error")
                return

            save_path = os.path.join(DOWNLOAD_DIR, filename)
            with open(save_path, "wb") as f:
                f.write(file_bytes)

            size = len(file_bytes)
            self._log(
                f"Received {filename} from {sender}\n"
                f"  Size   : {size:,} bytes\n"
                f"  Hash   : {file_hash[:32]}...\n"
                f"  Status : SHA-256 verified OK\n"
                f"  Saved  : {save_path}",
                "success")

            self.root.after(0, self._add_hist,
                            "Received", filename, sender, size, "Verified OK")
            self.root.after(0, messagebox.showinfo,
                            "File Received",
                            f"{filename} received from {sender}\n"
                            f"SHA-256 verified\nSaved to:\n{save_path}")
        except Exception as e:
            self._log(f"Decrypt error: {e}", "error")

    # ── Receive loop ───────────────────────────────────────────────────────────

    def _start_receive_thread(self):
        threading.Thread(target=self._receive_loop, daemon=True).start()

    def _receive_loop(self):
        while self._connected:
            try:
                pkt   = recv_packet(self.sock)
                ptype = pkt.get("type")

                if ptype == "incoming_file":
                    threading.Thread(target=self._receive_file,
                                     args=(pkt,), daemon=True).start()
                elif ptype == "user_list":
                    self.users = pkt.get("users", {})
                    self.root.after(0, self._refresh_ulist)
                elif ptype == "system":
                    self._log(pkt.get("message", ""), "info")
                elif ptype == "transfer_ok":
                    self._log(pkt.get("message", "Transfer OK"), "success")
                elif ptype == "error":
                    self._log(pkt.get("message", "Error"), "error")
                elif ptype == "stats":
                    self.root.after(0, self._update_stats, pkt)
                elif ptype == "pong":
                    pass

            except Exception:
                break

        # Connection dropped — update UI
        self._connected = False
        self.root.after(0, self._show_disconnected)

    def _show_disconnected(self):
        self._conn_lbl.config(
            text="Disconnected — click Reconnect to log back in",
            fg="#FF6B6B")
        self._reconnect_btn.pack(fill="x", padx=8, pady=(2, 8))
        self._log("Connection lost. Click  Reconnect  in the sidebar.", "error")

    def _reconnect(self):
        """Close this window and open a fresh AuthWindow."""
        try:
            self.sock.close()
        except Exception:
            pass
        if self._stats_job:
            try:
                self.root.after_cancel(self._stats_job)
            except Exception:
                pass
        self.root.destroy()
        AuthWindow().root.mainloop()

    # ── Attack stats ───────────────────────────────────────────────────────────

    def _request_stats(self):
        if not self._connected:
            self._log("Cannot fetch stats — not connected.", "warn")
            return
        try:
            # stats_request is in NO_REPLAY_CHECK on server — no nonce needed
            send_packet(self.sock, {"type": "stats_request"})
        except Exception as e:
            self._log(f"Stats request failed: {e}", "error")

    def _on_tab_change(self, event):
        """Auto-refresh stats when user switches to the Attack Monitor tab."""
        tab = self._nb.tab(self._nb.select(), "text")
        if tab == "Attack Monitor":
            self._request_stats()

    def _update_stats(self, pkt: dict):
        stats  = pkt.get("stats", {})
        events = pkt.get("events", [])

        for key, lbl in self._stat_lbls.items():
            lbl.config(text=str(stats.get(key, 0)))

        self._atk_log.config(state="normal")
        self._atk_log.delete("1.0", "end")

        if not events:
            self._atk_log.insert(
                "end",
                "No attack events recorded yet.\n\n"
                "Events appear here when:\n"
                "  • An IP sends more than 10 requests in 10 seconds  (DoS)\n"
                "  • A packet with a duplicate nonce is received       (Replay)\n"
                "  • A user reconnects with a changed public key       (MITM)\n")
        else:
            for ev in reversed(events):
                self._atk_log.insert(
                    "end",
                    f"[{ev['timestamp']}]  {ev['type']:8s}  "
                    f"{ev['source']:20s}  {ev['detail']}\n")

        self._atk_log.config(state="disabled")

    # ── UI helpers ─────────────────────────────────────────────────────────────

    def _refresh_ulist(self):
        self._ulist.delete(0, "end")
        for u in sorted(self.users.keys()):
            label = u + ("  (you)" if u == self.username else "")
            self._ulist.insert("end", label)

    def _log(self, msg: str, tag: str = None):
        ts   = time.strftime("%H:%M:%S")
        line = f"[{ts}] {msg}\n"
        self.root.after(0, self._append_log, line, tag)

    def _append_log(self, line: str, tag: str):
        self._log_area.config(state="normal")
        if tag:
            self._log_area.insert("end", line, tag)
        else:
            self._log_area.insert("end", line)
        self._log_area.see("end")
        self._log_area.config(state="disabled")

    def _add_hist(self, direction, filename, peer, size, status):
        ts = time.strftime("%H:%M:%S")
        self._hist.insert("", 0, values=(
            ts, direction, filename, peer, f"{size:,} B", status))

    def _on_close(self):
        self._connected = False
        if self._stats_job:
            try:
                self.root.after_cancel(self._stats_job)
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.root.destroy()

    def run(self):
        self.root.mainloop()


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    AuthWindow().root.mainloop()