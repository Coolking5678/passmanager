"""
database.py
SQLite database initialization and CRUD operations for the password manager.
"""

import sqlite3
from pathlib import Path

# Store the database next to the project root
DB_PATH = Path(__file__).resolve().parent.parent / "vault.db"


def _get_connection() -> sqlite3.Connection:
    """Create and return a database connection with row_factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database() -> None:
    """
    Create the database and required tables if they do not already exist.

    Tables:
        config      – Stores the bcrypt hash of the master password and the
                      PBKDF2 salt used for key derivation.
        credentials – Stores website, username, and Fernet-encrypted password.
    """
    with _get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS config (
                id                  INTEGER PRIMARY KEY CHECK (id = 1),
                master_password_hash BLOB    NOT NULL,
                pbkdf2_salt          BLOB    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                website            TEXT    NOT NULL,
                username           TEXT    NOT NULL,
                encrypted_password BLOB    NOT NULL
            )
        """)
        conn.commit()


# ---------------------------------------------------------------------------
# Config table helpers
# ---------------------------------------------------------------------------

def save_master_config(master_hash: bytes, pbkdf2_salt: bytes) -> None:
    """
    Persist the master password hash and PBKDF2 salt.
    Uses INSERT OR REPLACE to enforce a single-row constraint (id = 1).
    """
    with _get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO config (id, master_password_hash, pbkdf2_salt)"
            " VALUES (1, ?, ?)",
            (master_hash, pbkdf2_salt),
        )
        conn.commit()


def get_master_config() -> sqlite3.Row | None:
    """
    Retrieve the master password hash and PBKDF2 salt.

    Returns:
        A Row with keys 'master_password_hash' and 'pbkdf2_salt',
        or None if the vault has not been set up yet.
    """
    with _get_connection() as conn:
        row = conn.execute(
            "SELECT master_password_hash, pbkdf2_salt FROM config WHERE id = 1"
        ).fetchone()
    return row


# ---------------------------------------------------------------------------
# Credentials CRUD
# ---------------------------------------------------------------------------

def add_credential(website: str, username: str, encrypted_password: bytes) -> None:
    """Insert a new credential record into the database."""
    with _get_connection() as conn:
        conn.execute(
            "INSERT INTO credentials (website, username, encrypted_password)"
            " VALUES (?, ?, ?)",
            (website, username, encrypted_password),
        )
        conn.commit()


def get_all_credentials() -> list[sqlite3.Row]:
    """Return all stored credentials ordered by website name."""
    with _get_connection() as conn:
        rows = conn.execute(
            "SELECT id, website, username, encrypted_password"
            " FROM credentials ORDER BY website ASC"
        ).fetchall()
    return rows


def delete_credential(credential_id: int) -> None:
    """Delete a credential record by its primary key."""
    with _get_connection() as conn:
        conn.execute("DELETE FROM credentials WHERE id = ?", (credential_id,))
        conn.commit()
