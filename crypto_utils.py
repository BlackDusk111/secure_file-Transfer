"""
crypto_utils.py — Cryptographic Utilities for SecureTransfer
=============================================================
Provides RSA-2048 key generation, AES-256-CBC file encryption/decryption,
hybrid encryption helpers, SHA-256 hashing, and file integrity verification.

All functions are stateless and independently unit-testable.
"""

import os
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


# ── RSA Key Management ────────────────────────────────────────────────────────

def generate_rsa_keypair():
    """
    Generate a fresh RSA-2048 key pair.
    Returns (private_key, public_key) as cryptography key objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key, private_key.public_key()


def serialize_public_key(public_key):
    """
    Convert a public key object to a PEM-encoded string for network transmission.
    Returns: str (PEM text)
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")


def load_public_key(pem_str):
    """
    Load a PEM-encoded public key string back into a key object.
    Returns: public_key object
    """
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


# ── RSA Encrypt / Decrypt (for small data — used for AES key wrapping) ────────

def rsa_encrypt(public_key, data: bytes) -> bytes:
    """
    Encrypt bytes using RSA-2048 with OAEP/SHA-256 padding.
    Used to wrap the AES session key before transmission.
    Returns: encrypted bytes
    """
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    """
    Decrypt RSA-OAEP encrypted bytes using the private key.
    Returns: original plaintext bytes
    """
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ── AES-256-CBC File Encryption ───────────────────────────────────────────────

def aes_encrypt_bytes(data: bytes):
    """
    Encrypt arbitrary bytes using AES-256-CBC.
    Generates a fresh random 32-byte key and 16-byte IV for every call.

    Args:
        data: raw bytes to encrypt (file content)

    Returns:
        ciphertext_b64 (str), iv_b64 (str), key_b64 (str)
    """
    key = os.urandom(32)   # 256-bit AES key
    iv  = os.urandom(16)   # 128-bit IV

    padder = PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return (
        base64.b64encode(ciphertext).decode(),
        base64.b64encode(iv).decode(),
        base64.b64encode(key).decode()
    )


def aes_decrypt_bytes(ciphertext_b64: str, iv_b64: str, key_b64: str) -> bytes:
    """
    Decrypt AES-256-CBC encrypted data back to original bytes.

    Args:
        ciphertext_b64: base64-encoded ciphertext
        iv_b64:         base64-encoded IV
        key_b64:        base64-encoded AES key

    Returns:
        original plaintext bytes
    """
    ciphertext = base64.b64decode(ciphertext_b64)
    iv         = base64.b64decode(iv_b64)
    key        = base64.b64decode(key_b64)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


# ── Hybrid Encrypt / Decrypt (RSA wraps the AES key) ─────────────────────────

def hybrid_encrypt_file(file_bytes: bytes, recipient_public_key):
    """
    Encrypt a file using hybrid encryption:
      1. AES-256-CBC encrypts the file content
      2. RSA-OAEP encrypts the AES key using the recipient's public key

    Returns dict with all fields needed for transmission.
    """
    ct_b64, iv_b64, key_b64 = aes_encrypt_bytes(file_bytes)
    aes_key_raw = base64.b64decode(key_b64)
    encrypted_key = rsa_encrypt(recipient_public_key, aes_key_raw)

    return {
        "ciphertext":    ct_b64,
        "iv":            iv_b64,
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "file_hash":     sha256_bytes(file_bytes)   # integrity check
    }


def hybrid_decrypt_file(payload: dict, private_key) -> bytes:
    """
    Decrypt a hybrid-encrypted file payload.
    Recovers the AES key via RSA, then decrypts the file content.

    Returns: original file bytes
    """
    encrypted_key = base64.b64decode(payload["encrypted_key"])
    aes_key_raw   = rsa_decrypt(private_key, encrypted_key)
    key_b64       = base64.b64encode(aes_key_raw).decode()

    return aes_decrypt_bytes(payload["ciphertext"], payload["iv"], key_b64)


# ── Hashing ───────────────────────────────────────────────────────────────────

def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(filepath: str) -> str:
    """Return the SHA-256 hex digest of a file on disk."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_password(password: str) -> str:
    """Return the SHA-256 hex digest of a password string."""
    return hashlib.sha256(password.encode()).hexdigest()


def verify_file_integrity(received_bytes: bytes, expected_hash: str) -> bool:
    """
    Verify that received file bytes match the sender's reported SHA-256 hash.
    Used to detect corruption or tampering in transit.
    """
    return sha256_bytes(received_bytes) == expected_hash


# ── Nonce Generation (for replay attack prevention) ───────────────────────────

def generate_nonce() -> str:
    """Generate a cryptographically random 16-byte nonce as a hex string."""
    return os.urandom(16).hex()

