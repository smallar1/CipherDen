"""
vault.py — CipherDen vault CRUD operations.

All reads decrypt password_enc on the fly using the session key.
Passwords are never written to the database as plaintext.

AAD for each password field: f"{entry_id}:password".encode()
This binds the ciphertext to its specific row, preventing ciphertext
transplant attacks between entries.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

from cipherden.exceptions import NotFoundError
from cipherden.vault.crypto import decrypt, encrypt
from cipherden.vault.db import open_db
from cipherden.vault.init import VAULT_FILE
from cipherden.vault.models import EntryCreate, EntryRead, EntryUpdate

_UPDATABLE_COLUMNS = frozenset({"title", "username", "password_enc", "url", "notes"})


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_to_entry(row: sqlite3.Row, key: bytearray) -> EntryRead:
    entry_id = row["id"]
    aad = f"{entry_id}:password".encode()
    password = decrypt(key, bytes(row["password_enc"]), aad=aad).decode()
    return EntryRead(
        id=entry_id,
        title=row["title"],
        username=row["username"],
        password=password,
        url=row["url"],
        notes=row["notes"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def add_entry(
    key: bytearray,
    data: EntryCreate,
    vault_path: Path = VAULT_FILE,
) -> EntryRead:
    """Insert a new entry. Returns the created entry with its generated ID."""
    entry_id = str(uuid.uuid4())
    now = _utcnow()
    aad = f"{entry_id}:password".encode()
    password_enc = encrypt(key, data.password.encode(), aad=aad)

    conn = open_db(vault_path)
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO entries
                    (id, title, username, password_enc, url, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (entry_id, data.title, data.username, password_enc, data.url, data.notes, now, now),
            )
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
    finally:
        conn.close()

    return _row_to_entry(row, key)


def get_entry(
    key: bytearray,
    entry_id: str,
    vault_path: Path = VAULT_FILE,
) -> EntryRead:
    """Fetch and decrypt a single entry by ID. Raises NotFoundError if missing."""
    conn = open_db(vault_path)
    try:
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
    finally:
        conn.close()

    if row is None:
        raise NotFoundError(f"Entry '{entry_id}' not found.")

    return _row_to_entry(row, key)


def get_entries_by_title(
    key: bytearray,
    title: str,
    vault_path: Path = VAULT_FILE,
) -> list[EntryRead]:
    """Return all entries whose title matches *title* (case-insensitive)."""
    conn = open_db(vault_path)
    try:
        rows = conn.execute(
            "SELECT * FROM entries WHERE title = ? COLLATE NOCASE ORDER BY title COLLATE NOCASE",
            (title,),
        ).fetchall()
    finally:
        conn.close()

    return [_row_to_entry(row, key) for row in rows]


def list_entries(
    key: bytearray,
    vault_path: Path = VAULT_FILE,
) -> list[EntryRead]:
    """Return all entries, each fully decrypted."""
    conn = open_db(vault_path)
    try:
        rows = conn.execute("SELECT * FROM entries ORDER BY title COLLATE NOCASE").fetchall()
    finally:
        conn.close()

    return [_row_to_entry(row, key) for row in rows]


def update_entry(
    key: bytearray,
    entry_id: str,
    data: EntryUpdate,
    vault_path: Path = VAULT_FILE,
) -> EntryRead:
    """
    Partially update an entry. Only non-None fields are changed.
    Raises NotFoundError if the entry does not exist.
    Raises ValueError if no fields are set on data.
    """
    if not data.has_updates():
        raise ValueError("EntryUpdate has no fields set.")

    conn = open_db(vault_path)
    try:
        row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"Entry '{entry_id}' not found.")

        fields: dict = {}
        if data.title is not None:
            fields["title"] = data.title
        if data.username is not None:
            fields["username"] = data.username
        if data.password is not None:
            aad = f"{entry_id}:password".encode()
            fields["password_enc"] = encrypt(key, data.password.encode(), aad=aad)
        if data.url is not None:
            fields["url"] = data.url
        if data.notes is not None:
            fields["notes"] = data.notes

        fields["updated_at"] = _utcnow()

        invalid = set(fields) - (_UPDATABLE_COLUMNS | {"updated_at"})
        if invalid:
            raise ValueError(f"Unexpected column(s): {invalid}")

        set_clause = ", ".join(f"{col} = ?" for col in fields)
        with conn:
            conn.execute(
                f"UPDATE entries SET {set_clause} WHERE id = ?",  # noqa: S608
                (*fields.values(), entry_id),
            )

        row = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
    finally:
        conn.close()

    return _row_to_entry(row, key)


def delete_entry(
    entry_id: str,
    vault_path: Path = VAULT_FILE,
) -> None:
    """
    Delete an entry by ID. Raises NotFoundError if it does not exist.
    Note: key is not required — deletion doesn't touch encrypted data.
    """
    conn = open_db(vault_path)
    try:
        row = conn.execute("SELECT id FROM entries WHERE id = ?", (entry_id,)).fetchone()
        if row is None:
            raise NotFoundError(f"Entry '{entry_id}' not found.")
        with conn:
            conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    finally:
        conn.close()
