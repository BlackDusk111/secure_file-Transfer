"""
attack_detector.py — Attack Detection Module for SecureTransfer
===============================================================
Detects and logs three categories of network attacks:

  1. DoS (Denial of Service)  — rate limiting per IP address
  2. Replay attacks           — nonce + timestamp validation
  3. MITM (Man-in-the-Middle) — public key fingerprint verification

All state is held in memory. Detection events are written to attack_log.json.
"""

import time
import json
import os
import threading
from collections import defaultdict
from typing import Dict, List, Set

ATTACK_LOG = "attack_log.json"

# ── Configuration constants ───────────────────────────────────────────────────
DOS_MAX_REQUESTS   = 10    # max requests allowed per IP per window
DOS_WINDOW_SECONDS = 10    # rolling time window in seconds
REPLAY_MAX_AGE     = 30    # nonces older than 30 seconds are rejected


class AttackDetector:
    """
    Central detection engine. One instance shared across all server threads.
    All public methods are thread-safe via internal locking.
    """

    def __init__(self):
        self._lock = threading.Lock()

        # DoS tracking: ip -> list of request timestamps
        self._request_times: Dict[str, list] = defaultdict(list)

        # Replay tracking: set of nonces seen
        self._seen_nonces: Set[str] = set()

        # MITM tracking: username -> known public key fingerprint
        self._known_keys: Dict[str, str] = {}

        # In-memory log list (also written to file)
        self._log: List[dict] = []

        self._load_log()

    # ── DoS Detection ─────────────────────────────────────────────────────────

    def check_dos(self, ip: str) -> bool:
        """
        Rate-limit check. Returns True if the request is ALLOWED,
        False if the IP has exceeded the request threshold (DoS detected).
        """
        now = time.time()
        with self._lock:
            # Keep only timestamps within the rolling window
            self._request_times[ip] = [
                t for t in self._request_times[ip]
                if now - t < DOS_WINDOW_SECONDS
            ]
            self._request_times[ip].append(now)
            count = len(self._request_times[ip])

            if count > DOS_MAX_REQUESTS:
                self._record_event("DoS", ip,
                    f"{count} requests in {DOS_WINDOW_SECONDS}s (limit {DOS_MAX_REQUESTS})")
                return False   # block this request
            return True        # allow this request

    def get_request_count(self, ip: str) -> int:
        """Return current request count for an IP (for display purposes)."""
        now = time.time()
        with self._lock:
            return len([
                t for t in self._request_times[ip]
                if now - t < DOS_WINDOW_SECONDS
            ])

    # ── Replay Attack Detection ───────────────────────────────────────────────

    def check_replay(self, nonce: str, timestamp: float) -> bool:
        """
        Validate a nonce + timestamp pair.
        Returns True if the packet is FRESH (not a replay).
        Returns False if the nonce was seen before or the timestamp is stale.
        """
        now = time.time()
        age = now - timestamp

        with self._lock:
            # Reject stale packets
            if age > REPLAY_MAX_AGE:
                self._record_event("Replay", "unknown",
                    f"Stale packet: {age:.1f}s old (max {REPLAY_MAX_AGE}s)")
                return False

            # Reject duplicate nonces
            if nonce in self._seen_nonces:
                self._record_event("Replay", "unknown",
                    f"Duplicate nonce detected: {nonce[:16]}...")
                return False

            self._seen_nonces.add(nonce)

            # Prune old nonces periodically to save memory
            if len(self._seen_nonces) > 10000:
                self._seen_nonces.clear()

            return True

    # ── MITM Detection ────────────────────────────────────────────────────────

    def register_key(self, username: str, public_key_pem: str):
        """
        Record a user's public key fingerprint on first connection.
        This is the Trust On First Use (TOFU) model.
        """
        fingerprint = self._fingerprint(public_key_pem)
        with self._lock:
            if username not in self._known_keys:
                self._known_keys[username] = fingerprint

    def check_mitm(self, username: str, public_key_pem: str) -> bool:
        """
        Verify that a returning user's public key matches the stored fingerprint.
        Returns True if the key is TRUSTED (matches or is new).
        Returns False if the key has changed — potential MITM attack.
        """
        fingerprint = self._fingerprint(public_key_pem)
        with self._lock:
            known = self._known_keys.get(username)
            if known is None:
                # First time seeing this user — register and trust
                self._known_keys[username] = fingerprint
                return True

            if known != fingerprint:
                self._record_event("MITM", username,
                    f"Public key mismatch. Expected: {known[:16]}... Got: {fingerprint[:16]}...")
                return False

            return True

    # ── Event Logging ─────────────────────────────────────────────────────────

    def get_recent_events(self, n: int = 20) -> list:
        """Return the n most recent attack events."""
        with self._lock:
            return list(self._log[-n:])

    def get_stats(self) -> dict:
        """Return summary counts by attack type."""
        with self._lock:
            stats = {"DoS": 0, "Replay": 0, "MITM": 0, "total": len(self._log)}
            for event in self._log:
                t = event.get("type", "")
                if t in stats:
                    stats[t] += 1
            return stats

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fingerprint(self, pem: str) -> str:
        """SHA-256 fingerprint of a PEM public key string."""
        import hashlib
        return hashlib.sha256(pem.encode()).hexdigest()

    def _record_event(self, attack_type: str, source: str, detail: str):
        """Append an attack event to the in-memory log and persist to file."""
        event = {
            "type":      attack_type,
            "source":    source,
            "detail":    detail,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self._log.append(event)
        self._save_log()
        print(f"  [ATTACK DETECTED] {attack_type} from {source}: {detail}")

    def _save_log(self):
        """Write the full log to attack_log.json."""
        try:
            with open(ATTACK_LOG, "w") as f:
                json.dump(self._log, f, indent=2)
        except Exception:
            pass

    def _load_log(self):
        """Load existing log from disk if present."""
        if os.path.exists(ATTACK_LOG):
            try:
                with open(ATTACK_LOG) as f:
                    self._log = json.load(f)
            except Exception:
                self._log = []

    def update_key(self, username: str, public_key_pem: str):
        """
        Overwrite the stored key fingerprint for a user.
        Called when a returning user reconnects with a new session key.
        This is expected behaviour since RSA keys are regenerated each session.
        """
        fingerprint = self._fingerprint(public_key_pem)
        with self._lock:
            self._known_keys[username] = fingerprint