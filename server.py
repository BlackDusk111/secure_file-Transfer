"""
server.py — SecureTransfer Server
==================================
Multi-threaded TCP server that:
  - Authenticates users (SHA-256 hashed passwords in users.json)
  - Performs RSA-2048 public key exchange
  - Receives AES-256 encrypted file transfers
  - Routes files to intended recipients
  - Logs all transfers to transfer_log.json
  - Detects DoS, replay, and MITM attacks via AttackDetector

Usage:
    python server.py
"""

import socket
import threading
import json
import os
import time
import struct

from crypto_utils import hash_password, generate_nonce, verify_file_integrity
from attack_detector import AttackDetector

# ── Configuration ─────────────────────────────────────────────────────────────
HOST         = "0.0.0.0"
PORT         = 65433
USERS_FILE   = "users.json"
TRANSFER_LOG = "transfer_log.json"
RECEIVED_DIR = "server_received"

os.makedirs(RECEIVED_DIR, exist_ok=True)

# ── Shared state (protected by locks) ─────────────────────────────────────────
clients_lock = threading.Lock()
clients: dict = {}          # username -> {"socket": sock, "public_key_pem": str}
log_lock      = threading.Lock()
detector      = AttackDetector()

# Packets that do NOT need a nonce/timestamp (control messages)
NO_REPLAY_CHECK = {"ping", "stats_request", "file_request"}


# ── Persistence helpers ────────────────────────────────────────────────────────

def load_users() -> dict:
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE) as f:
            return json.load(f)
    return {}


def save_users(users: dict):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def load_transfer_log() -> list:
    if os.path.exists(TRANSFER_LOG):
        with open(TRANSFER_LOG) as f:
            return json.load(f)
    return []


def append_transfer_log(entry: dict):
    with log_lock:
        log = load_transfer_log()
        log.append(entry)
        with open(TRANSFER_LOG, "w") as f:
            json.dump(log, f, indent=2)


# ── Socket send / receive helpers ─────────────────────────────────────────────

def send_packet(sock: socket.socket, data: dict):
    """Serialize dict to JSON and send with a 4-byte length prefix."""
    raw = json.dumps(data).encode("utf-8")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def recv_packet(sock: socket.socket) -> dict:
    """Receive a length-prefixed JSON packet and return as dict."""
    header = _recv_exactly(sock, 4)
    if not header:
        raise ConnectionError("Client disconnected")
    length = struct.unpack("!I", header)[0]
    raw = _recv_exactly(sock, length)
    return json.loads(raw.decode("utf-8"))


def _recv_exactly(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf


# ── Broadcast helpers ──────────────────────────────────────────────────────────

def broadcast_user_list():
    """Send the current online user list (with public keys) to every client."""
    with clients_lock:
        user_list = {u: d["public_key_pem"] for u, d in clients.items()}
        for username, data in clients.items():
            try:
                send_packet(data["socket"], {"type": "user_list", "users": user_list})
            except Exception:
                pass


def notify_all(message: str, exclude: str = None):
    """Send a system notification to all clients except the excluded one."""
    with clients_lock:
        for username, data in clients.items():
            if username == exclude:
                continue
            try:
                send_packet(data["socket"], {"type": "system", "message": message})
            except Exception:
                pass


# ── Client handler ─────────────────────────────────────────────────────────────

def handle_client(sock: socket.socket, addr: tuple):
    """
    Per-client thread. Handles full lifecycle:
    auth → key exchange → file transfer loop → cleanup.
    """
    ip       = addr[0]
    username = None

    try:
        # ── DoS check on connection ────────────────────────────────────────
        if not detector.check_dos(ip):
            send_packet(sock, {"type": "error",
                               "message": "Rate limit exceeded. Try again later."})
            sock.close()
            return

        # ── Authentication ─────────────────────────────────────────────────
        auth = recv_packet(sock)
        if not auth or auth.get("type") not in ("login", "register"):
            send_packet(sock, {"type": "error", "message": "Bad auth packet"})
            sock.close()
            return

        username = auth.get("username", "").strip()
        password = auth.get("password", "")
        mode     = auth.get("type")
        pw_hash  = hash_password(password)
        users    = load_users()

        if mode == "register":
            if username in users:
                send_packet(sock, {"type": "error",
                                   "message": "Username already exists"})
                sock.close()
                return
            users[username] = pw_hash
            save_users(users)
            send_packet(sock, {"type": "auth_ok",
                               "message": "Registered successfully"})

        elif mode == "login":
            if username not in users or users[username] != pw_hash:
                send_packet(sock, {"type": "error",
                                   "message": "Invalid credentials"})
                sock.close()
                return
            send_packet(sock, {"type": "auth_ok", "message": "Login successful"})

        print(f"  [{mode.upper()}] {username} from {ip}")

        # ── RSA public key exchange ────────────────────────────────────────
        key_pkt = recv_packet(sock)
        if key_pkt.get("type") != "public_key":
            sock.close()
            return

        public_key_pem = key_pkt["pem"]

        # ── MITM detection (warn only — do NOT block reconnections) ────────
        # Because RSA keys are regenerated every session, a key change is
        # expected on reconnect. We log it as a warning but still allow login.
        # A real production system would use persistent keys stored by the client.
        mitm_ok = detector.check_mitm(username, public_key_pem)
        if not mitm_ok:
            # Update stored key to the new one so subsequent reconnects work
            detector.update_key(username, public_key_pem)
            send_packet(sock, {
                "type":    "system",
                "message": "WARNING: Your public key changed (new session key registered)."
            })
            print(f"  [MITM WARNING] {username} — key updated for new session")

        detector.register_key(username, public_key_pem)

        # ── Add to online registry ─────────────────────────────────────────
        with clients_lock:
            clients[username] = {"socket": sock, "public_key_pem": public_key_pem}

        # Send current user list to new client
        with clients_lock:
            user_list = {u: d["public_key_pem"] for u, d in clients.items()}
        send_packet(sock, {"type": "user_list", "users": user_list})

        notify_all(f"{username} joined", exclude=username)
        broadcast_user_list()
        print(f"  [ONLINE] {username} — {len(clients)} user(s) connected")

        # ── Main packet loop ───────────────────────────────────────────────
        while True:
            pkt   = recv_packet(sock)
            ptype = pkt.get("type")

            # DoS check every packet
            if not detector.check_dos(ip):
                send_packet(sock, {"type": "error",
                                   "message": "Rate limit exceeded"})
                break

            # Replay check — skip for control packets that have no nonce
            if ptype not in NO_REPLAY_CHECK:
                nonce     = pkt.get("nonce", "")
                timestamp = pkt.get("timestamp", 0)
                if not detector.check_replay(nonce, timestamp):
                    send_packet(sock, {"type": "error",
                                       "message": "Replay attack detected — packet rejected"})
                    continue

            if ptype == "file_transfer":
                _handle_file_transfer(pkt, username, sock)

            elif ptype == "file_request":
                _handle_file_request(pkt, username, sock)

            elif ptype == "ping":
                send_packet(sock, {"type": "pong"})

            elif ptype == "stats_request":
                # Return attack stats + recent 20 events
                send_packet(sock, {
                    "type":   "stats",
                    "stats":  detector.get_stats(),
                    "events": detector.get_recent_events(20)
                })

    except (ConnectionError, json.JSONDecodeError, OSError):
        pass

    finally:
        if username:
            with clients_lock:
                clients.pop(username, None)
            notify_all(f"{username} disconnected")
            broadcast_user_list()
            print(f"  [OFFLINE] {username}")
        try:
            sock.close()
        except Exception:
            pass


def _handle_file_transfer(pkt: dict, sender: str, sender_sock: socket.socket):
    """Route an encrypted file to the recipient."""
    recipient  = pkt.get("recipient")
    filename   = pkt.get("filename", "unknown_file")
    ciphertext = pkt.get("ciphertext", "")
    iv         = pkt.get("iv", "")
    enc_key    = pkt.get("encrypted_key", "")
    file_hash  = pkt.get("file_hash", "")
    file_size  = pkt.get("file_size", 0)

    print(f"  [TRANSFER] {sender} -> {recipient}: {filename} ({file_size} bytes)")

    append_transfer_log({
        "sender":    sender,
        "recipient": recipient,
        "filename":  filename,
        "file_hash": file_hash,
        "file_size": file_size,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "status":    "relayed"
    })

    with clients_lock:
        recipient_data = clients.get(recipient)

    if recipient_data:
        try:
            send_packet(recipient_data["socket"], {
                "type":          "incoming_file",
                "sender":        sender,
                "filename":      filename,
                "ciphertext":    ciphertext,
                "iv":            iv,
                "encrypted_key": enc_key,
                "file_hash":     file_hash,
                "file_size":     file_size
            })
            send_packet(sender_sock, {
                "type":    "transfer_ok",
                "message": f"{filename} delivered to {recipient}"
            })
        except Exception as e:
            send_packet(sender_sock, {
                "type":    "error",
                "message": f"Failed to deliver to {recipient}: {e}"
            })
    else:
        send_packet(sender_sock, {
            "type":    "error",
            "message": f"{recipient} is not online"
        })


def _handle_file_request(pkt: dict, requester: str, requester_sock: socket.socket):
    """Respond with list of files on the server."""
    files = []
    for fname in os.listdir(RECEIVED_DIR):
        fpath = os.path.join(RECEIVED_DIR, fname)
        files.append({"name": fname, "size": os.path.getsize(fpath)})
    send_packet(requester_sock, {"type": "file_list", "files": files})


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(20)
    server_sock.settimeout(1.0)   # unblocks every 1s so Ctrl+C works cleanly

    import attack_detector as _ad
    print("=" * 55)
    print("  SecureTransfer Server")
    print(f"  Listening on {HOST}:{PORT}")
    print(f"  DoS limit : {_ad.DOS_MAX_REQUESTS} req / {_ad.DOS_WINDOW_SECONDS}s")
    print(f"  Replay TTL: {_ad.REPLAY_MAX_AGE}s")
    print("  Press Ctrl+C to stop.")
    print("=" * 55)

    running = True
    while running:
        try:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client,
                                 args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            continue
        except KeyboardInterrupt:
            print("\n  Server shutting down.")
            running = False
        except OSError:
            break

    try:
        server_sock.close()
    except Exception:
        pass


if __name__ == "__main__":
    main()