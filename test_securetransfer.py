"""
test_securetransfer.py — Unit Tests for SecureTransfer
=======================================================
Run with:
    python -m unittest test_securetransfer -v

Tests cover:
  - AES-256-CBC encryption and decryption
  - RSA-2048 key generation and hybrid encryption
  - File integrity verification
  - Password hashing
  - Attack detection (DoS, replay, MITM)
"""

import unittest
import time
import base64

from crypto_utils import (
    generate_rsa_keypair, serialize_public_key, load_public_key,
    aes_encrypt_bytes, aes_decrypt_bytes,
    hybrid_encrypt_file, hybrid_decrypt_file,
    sha256_bytes, hash_password,
    verify_file_integrity, generate_nonce,
    rsa_encrypt, rsa_decrypt
)
from attack_detector import AttackDetector


# ══════════════════════════════════════════════════════════════════════════════
# AES TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAESEncryption(unittest.TestCase):

    def test_encrypt_returns_three_values(self):
        """aes_encrypt_bytes must return ciphertext, iv, and key."""
        ct, iv, key = aes_encrypt_bytes(b"hello world")
        self.assertTrue(len(ct) > 0)
        self.assertTrue(len(iv) > 0)
        self.assertTrue(len(key) > 0)

    def test_decrypt_recovers_original(self):
        """Decrypting the output of aes_encrypt_bytes must return the original bytes."""
        original = b"SecureTransfer test data 1234567890"
        ct, iv, key = aes_encrypt_bytes(original)
        result = aes_decrypt_bytes(ct, iv, key)
        self.assertEqual(result, original)

    def test_empty_bytes(self):
        """Empty bytes should encrypt and decrypt without error."""
        ct, iv, key = aes_encrypt_bytes(b"")
        result = aes_decrypt_bytes(ct, iv, key)
        self.assertEqual(result, b"")

    def test_large_file_bytes(self):
        """Large binary data (1 MB) must round-trip correctly."""
        import os
        data = os.urandom(1024 * 1024)
        ct, iv, key = aes_encrypt_bytes(data)
        result = aes_decrypt_bytes(ct, iv, key)
        self.assertEqual(result, data)

    def test_unique_key_per_call(self):
        """Every call to aes_encrypt_bytes must produce a unique key."""
        _, _, key1 = aes_encrypt_bytes(b"same data")
        _, _, key2 = aes_encrypt_bytes(b"same data")
        self.assertNotEqual(key1, key2)

    def test_unique_iv_per_call(self):
        """Every call to aes_encrypt_bytes must produce a unique IV."""
        _, iv1, _ = aes_encrypt_bytes(b"same data")
        _, iv2, _ = aes_encrypt_bytes(b"same data")
        self.assertNotEqual(iv1, iv2)

    def test_wrong_key_raises(self):
        """Decrypting with the wrong key must raise an exception."""
        ct, iv, _ = aes_encrypt_bytes(b"secret")
        _, _, wrong_key = aes_encrypt_bytes(b"other")
        with self.assertRaises(Exception):
            aes_decrypt_bytes(ct, iv, wrong_key)

    def test_wrong_iv_raises(self):
        """Decrypting with the wrong IV must produce incorrect output or raise."""
        data = b"important data here padded well!"
        ct, _, key = aes_encrypt_bytes(data)
        _, wrong_iv, _ = aes_encrypt_bytes(b"other")
        # Either raises or produces wrong output — both are acceptable
        try:
            result = aes_decrypt_bytes(ct, wrong_iv, key)
            self.assertNotEqual(result, data)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
# RSA TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestRSAEncryption(unittest.TestCase):

    def setUp(self):
        self.private_key, self.public_key = generate_rsa_keypair()

    def test_encrypt_decrypt_roundtrip(self):
        """RSA encrypt then decrypt must recover the original bytes."""
        data = b"aes-session-key-32-bytes-padding"
        encrypted = rsa_encrypt(self.public_key, data)
        decrypted = rsa_decrypt(self.private_key, encrypted)
        self.assertEqual(decrypted, data)

    def test_wrong_private_key_raises(self):
        """Decrypting with a different private key must raise an exception."""
        other_private, _ = generate_rsa_keypair()
        data = b"some key bytes here 123456789012"
        encrypted = rsa_encrypt(self.public_key, data)
        with self.assertRaises(Exception):
            rsa_decrypt(other_private, encrypted)

    def test_serialize_and_reload_public_key(self):
        """Serialised public key must reload and function identically."""
        pem = serialize_public_key(self.public_key)
        loaded = load_public_key(pem)
        data = b"test round trip 1234567890123456"
        enc = rsa_encrypt(loaded, data)
        dec = rsa_decrypt(self.private_key, enc)
        self.assertEqual(dec, data)

    def test_pem_is_string(self):
        """serialize_public_key must return a string starting with BEGIN."""
        pem = serialize_public_key(self.public_key)
        self.assertIsInstance(pem, str)
        self.assertIn("BEGIN PUBLIC KEY", pem)


# ══════════════════════════════════════════════════════════════════════════════
# HYBRID ENCRYPTION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestHybridEncryption(unittest.TestCase):

    def setUp(self):
        self.private_key, self.public_key = generate_rsa_keypair()

    def test_hybrid_file_roundtrip(self):
        """hybrid_encrypt_file then hybrid_decrypt_file must recover original bytes."""
        original = b"This is a test file content. 1234567890 abcdefghij."
        payload  = hybrid_encrypt_file(original, self.public_key)
        result   = hybrid_decrypt_file(payload, self.private_key)
        self.assertEqual(result, original)

    def test_hybrid_includes_hash(self):
        """Encrypted payload must include a file_hash field."""
        payload = hybrid_encrypt_file(b"test data", self.public_key)
        self.assertIn("file_hash", payload)
        self.assertEqual(len(payload["file_hash"]), 64)  # SHA-256 hex = 64 chars

    def test_wrong_private_key_fails(self):
        """Decryption with the wrong private key must raise an exception."""
        other_private, _ = generate_rsa_keypair()
        payload = hybrid_encrypt_file(b"confidential", self.public_key)
        with self.assertRaises(Exception):
            hybrid_decrypt_file(payload, other_private)


# ══════════════════════════════════════════════════════════════════════════════
# HASHING AND INTEGRITY TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestHashing(unittest.TestCase):

    def test_same_data_same_hash(self):
        """SHA-256 of the same bytes must always produce the same digest."""
        self.assertEqual(sha256_bytes(b"hello"), sha256_bytes(b"hello"))

    def test_different_data_different_hash(self):
        """Different inputs must produce different SHA-256 digests."""
        self.assertNotEqual(sha256_bytes(b"hello"), sha256_bytes(b"world"))

    def test_hash_is_64_chars(self):
        """SHA-256 hex digest must always be exactly 64 characters."""
        self.assertEqual(len(sha256_bytes(b"test")), 64)

    def test_password_same_hash(self):
        """Same password must always produce the same hash."""
        self.assertEqual(hash_password("mypassword"), hash_password("mypassword"))

    def test_different_passwords_different_hashes(self):
        """Different passwords must produce different hashes."""
        self.assertNotEqual(hash_password("pass1"), hash_password("pass2"))

    def test_integrity_pass(self):
        """verify_file_integrity must return True for unmodified bytes."""
        data = b"original file content"
        file_hash = sha256_bytes(data)
        self.assertTrue(verify_file_integrity(data, file_hash))

    def test_integrity_fail(self):
        """verify_file_integrity must return False if bytes were modified."""
        data     = b"original file content"
        tampered = b"tampered file content"
        file_hash = sha256_bytes(data)
        self.assertFalse(verify_file_integrity(tampered, file_hash))


# ══════════════════════════════════════════════════════════════════════════════
# ATTACK DETECTION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAttackDetector(unittest.TestCase):

    def setUp(self):
        self.detector = AttackDetector()

    # ── DoS ───────────────────────────────────────────────────────────────────

    def test_dos_allows_normal_traffic(self):
        """A small number of requests from one IP must be allowed."""
        for _ in range(5):
            result = self.detector.check_dos("192.168.1.1")
        self.assertTrue(result)

    def test_dos_blocks_flood(self):
        """Exceeding the request limit from one IP must be blocked."""
        ip = "10.0.0.99"
        results = [self.detector.check_dos(ip) for _ in range(20)]
        # First 10 allowed, subsequent ones blocked
        self.assertFalse(results[-1])

    def test_dos_different_ips_independent(self):
        """Rate limiting must be per IP — one IP flooding must not block another."""
        flood_ip  = "1.2.3.4"
        clean_ip  = "5.6.7.8"
        for _ in range(20):
            self.detector.check_dos(flood_ip)
        result = self.detector.check_dos(clean_ip)
        self.assertTrue(result)

    # ── Replay ────────────────────────────────────────────────────────────────

    def test_replay_fresh_packet_allowed(self):
        """A fresh nonce with a current timestamp must be accepted."""
        nonce = generate_nonce()
        result = self.detector.check_replay(nonce, time.time())
        self.assertTrue(result)

    def test_replay_duplicate_nonce_blocked(self):
        """Sending the same nonce twice must block the second attempt."""
        nonce = generate_nonce()
        self.detector.check_replay(nonce, time.time())
        result = self.detector.check_replay(nonce, time.time())
        self.assertFalse(result)

    def test_replay_stale_timestamp_blocked(self):
        """A packet with a timestamp older than the replay window must be rejected."""
        nonce = generate_nonce()
        old_time = time.time() - 9999  # far in the past
        result = self.detector.check_replay(nonce, old_time)
        self.assertFalse(result)

    # ── MITM ──────────────────────────────────────────────────────────────────

    def test_mitm_first_key_trusted(self):
        """A user's first public key must be accepted and stored."""
        _, pub = generate_rsa_keypair()
        pem = serialize_public_key(pub)
        result = self.detector.check_mitm("alice", pem)
        self.assertTrue(result)

    def test_mitm_same_key_trusted(self):
        """The same public key on subsequent connections must be accepted."""
        _, pub = generate_rsa_keypair()
        pem = serialize_public_key(pub)
        self.detector.check_mitm("bob", pem)
        result = self.detector.check_mitm("bob", pem)
        self.assertTrue(result)

    def test_mitm_changed_key_blocked(self):
        """A different public key for a known user must be flagged as MITM."""
        _, pub1 = generate_rsa_keypair()
        _, pub2 = generate_rsa_keypair()
        pem1 = serialize_public_key(pub1)
        pem2 = serialize_public_key(pub2)
        self.detector.check_mitm("charlie", pem1)  # register first key
        result = self.detector.check_mitm("charlie", pem2)  # different key
        self.assertFalse(result)

    def test_stats_count_attacks(self):
        """get_stats must return accurate counts after attacks are detected."""
        # Trigger a replay
        nonce = generate_nonce()
        self.detector.check_replay(nonce, time.time())
        self.detector.check_replay(nonce, time.time())  # duplicate
        stats = self.detector.get_stats()
        self.assertGreaterEqual(stats["Replay"], 1)


if __name__ == "__main__":
    unittest.main()