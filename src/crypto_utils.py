"""
crypto_utils.py
Handles hashing, salting, and symmetric encryption for the password manager.
"""

import os
import base64
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ---------------------------------------------------------------------------
# Master Password – bcrypt hashing
# ---------------------------------------------------------------------------

def hash_master_password(plain_text: str) -> bytes:
    """Hash and salt the master password using bcrypt."""
    return bcrypt.hashpw(plain_text.encode("utf-8"), bcrypt.gensalt())


def verify_master_password(plain_text: str, hashed: bytes) -> bool:
    """Return True if plain_text matches the stored bcrypt hash."""
    return bcrypt.checkpw(plain_text.encode("utf-8"), hashed)


# ---------------------------------------------------------------------------
# Key derivation – PBKDF2 → Fernet key
# ---------------------------------------------------------------------------

def derive_fernet_key(master_password: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-compatible key from the master password
    using PBKDF2HMAC with SHA-256.

    Args:
        master_password: The user's plain-text master password.
        salt: A random 16-byte salt stored in the config table.

    Returns:
        A URL-safe base64-encoded 32-byte key suitable for Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,  # NIST-recommended minimum (2023)
    )
    raw_key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def generate_pbkdf2_salt() -> bytes:
    """Generate a cryptographically random 16-byte salt."""
    return os.urandom(16)


# ---------------------------------------------------------------------------
# Symmetric encryption – Fernet
# ---------------------------------------------------------------------------

def encrypt_password(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt a plaintext password string using the provided Fernet key.

    Args:
        key: A valid Fernet key (output of derive_fernet_key).
        plaintext: The password string to encrypt.

    Returns:
        An encrypted byte string (Fernet token).
    """
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8"))


def decrypt_password(key: bytes, ciphertext: bytes) -> str:
    """
    Decrypt a Fernet-encrypted byte string back to a plaintext password.

    Args:
        key: The same Fernet key used during encryption.
        ciphertext: The encrypted Fernet token.

    Returns:
        The decrypted plaintext password string.
    """
    f = Fernet(key)
    return f.decrypt(ciphertext).decode("utf-8")
