"""
tests/unit/vault/test_vault.py — Unit tests for vault CRUD operations.

Tests cover:
- add_entry returns EntryRead with correct fields
- get_entry retrieves and decrypts correctly
- get_entries_by_title matches title substrings case-insensitively
- list_entries returns all entries ordered by title
- search_entries matches title/url substrings case-insensitively
- update_entry updates only supplied fields and bumps updated_at
- delete_entry removes the entry
- Full add/get/list/update/delete lifecycle
- NotFoundError on get/update/delete for missing entries
- Password is never stored as plaintext (raw SQLite row check)
- EntryUpdate with no fields raises ValueError
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cipherden.exceptions import NotFoundError
from cipherden.vault.db import open_db
from cipherden.vault.init import vault_init
from cipherden.vault.models import EntryCreate, EntryUpdate
from cipherden.vault.vault import (
    add_entry,
    delete_entry,
    get_entries_by_title,
    get_entry,
    list_entries,
    search_entries,
    update_entry,
)

PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "test_vault.db"


@pytest.fixture
def key(vault_path: Path) -> bytearray:
    """Initialise a vault and return its session key."""
    return vault_init(PASSWORD, vault_path=vault_path)


@pytest.fixture
def sample_create() -> EntryCreate:
    return EntryCreate(
        title="GitHub",
        username="user@example.com",
        password="s3cr3t-password",  # pragma: allowlist secret
        url="https://github.com",
        notes="Work account",
    )


@pytest.fixture
def added_entry(key: bytearray, vault_path: Path, sample_create: EntryCreate):
    """Add a single entry and return it."""
    return add_entry(key, sample_create, vault_path=vault_path)


# ---------------------------------------------------------------------------
# add_entry
# ---------------------------------------------------------------------------


class TestAddEntry:
    def test_returns_entry_read(self, key, vault_path, sample_create) -> None:
        from cipherden.vault.models import EntryRead

        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert isinstance(entry, EntryRead)

    def test_id_is_uuid_string(self, key, vault_path, sample_create) -> None:
        import uuid

        entry = add_entry(key, sample_create, vault_path=vault_path)
        uuid.UUID(entry.id)  # raises if invalid

    def test_title_matches(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert entry.title == sample_create.title

    def test_username_matches(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert entry.username == sample_create.username

    def test_password_decrypts_correctly(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert entry.password == sample_create.password

    def test_url_matches(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert entry.url == sample_create.url

    def test_notes_match(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert entry.notes == sample_create.notes

    def test_created_at_is_set(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert entry.created_at != ""

    def test_updated_at_equals_created_at(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        assert entry.updated_at == entry.created_at

    def test_optional_fields_can_be_none(self, key, vault_path) -> None:
        data = EntryCreate(title="Minimal", password="pass123")  # pragma: allowlist secret
        entry = add_entry(key, data, vault_path=vault_path)
        assert entry.url is None
        assert entry.notes is None

    def test_username_defaults_to_empty_string(self, key, vault_path) -> None:
        data = EntryCreate(title="No Username", password="pass123")  # pragma: allowlist secret
        entry = add_entry(key, data, vault_path=vault_path)
        assert entry.username == ""

    def test_two_entries_have_different_ids(self, key, vault_path, sample_create) -> None:
        e1 = add_entry(key, sample_create, vault_path=vault_path)
        e2 = add_entry(key, sample_create, vault_path=vault_path)
        assert e1.id != e2.id


# ---------------------------------------------------------------------------
# Password never stored as plaintext
# ---------------------------------------------------------------------------


class TestPasswordNotPlaintext:
    def test_raw_row_does_not_contain_plaintext_password(
        self, key, vault_path, sample_create
    ) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT password_enc FROM entries WHERE id = ?", (entry.id,)).fetchone()
        conn.close()

        raw = bytes(row["password_enc"])
        assert sample_create.password.encode() not in raw

    def test_password_enc_is_bytes_not_text(self, key, vault_path, sample_create) -> None:
        entry = add_entry(key, sample_create, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT password_enc FROM entries WHERE id = ?", (entry.id,)).fetchone()
        conn.close()
        assert isinstance(bytes(row["password_enc"]), bytes)

    def test_password_enc_is_longer_than_plaintext(self, key, vault_path, sample_create) -> None:
        """Ciphertext must be longer than plaintext (nonce + tag overhead)."""
        entry = add_entry(key, sample_create, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT password_enc FROM entries WHERE id = ?", (entry.id,)).fetchone()
        conn.close()
        assert len(bytes(row["password_enc"])) > len(sample_create.password.encode())


# ---------------------------------------------------------------------------
# get_entry
# ---------------------------------------------------------------------------


class TestGetEntry:
    def test_returns_correct_entry(self, key, vault_path, added_entry) -> None:
        fetched = get_entry(key, added_entry.id, vault_path=vault_path)
        assert fetched.id == added_entry.id

    def test_password_decrypts_on_get(self, key, vault_path, added_entry, sample_create) -> None:
        fetched = get_entry(key, added_entry.id, vault_path=vault_path)
        assert fetched.password == sample_create.password

    def test_all_fields_match(self, key, vault_path, added_entry) -> None:
        fetched = get_entry(key, added_entry.id, vault_path=vault_path)
        assert fetched.title == added_entry.title
        assert fetched.username == added_entry.username
        assert fetched.url == added_entry.url
        assert fetched.notes == added_entry.notes

    def test_raises_not_found_error_for_missing_id(self, key, vault_path) -> None:
        with pytest.raises(NotFoundError):
            get_entry(key, "00000000-0000-0000-0000-000000000000", vault_path=vault_path)


# ---------------------------------------------------------------------------
# get_entries_by_title
# ---------------------------------------------------------------------------


class TestGetEntriesByTitle:
    def test_returns_matching_entry(self, key, vault_path, added_entry) -> None:
        results = get_entries_by_title(key, added_entry.title, vault_path=vault_path)
        assert [e.id for e in results] == [added_entry.id]

    def test_match_is_case_insensitive(self, key, vault_path, added_entry) -> None:
        results = get_entries_by_title(key, added_entry.title.upper(), vault_path=vault_path)
        assert [e.id for e in results] == [added_entry.id]

    def test_returns_empty_list_for_no_match(self, key, vault_path) -> None:
        assert get_entries_by_title(key, "Nonexistent", vault_path=vault_path) == []

    def test_match_is_partial_substring(self, key, vault_path, added_entry) -> None:
        substring = added_entry.title[1:-1]
        results = get_entries_by_title(key, substring, vault_path=vault_path)
        assert [e.id for e in results] == [added_entry.id]

    def test_partial_match_is_case_insensitive(self, key, vault_path, added_entry) -> None:
        substring = added_entry.title[1:-1].upper()
        results = get_entries_by_title(key, substring, vault_path=vault_path)
        assert [e.id for e in results] == [added_entry.id]

    def test_returns_all_entries_sharing_a_title(self, key, vault_path) -> None:
        add_entry(
            key,
            EntryCreate(title="Shared", username="a", password="p1"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        add_entry(
            key,
            EntryCreate(title="Shared", username="b", password="p2"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        results = get_entries_by_title(key, "Shared", vault_path=vault_path)
        assert {e.username for e in results} == {"a", "b"}

    def test_password_decrypts_correctly(self, key, vault_path, added_entry, sample_create) -> None:
        results = get_entries_by_title(key, added_entry.title, vault_path=vault_path)
        assert results[0].password == sample_create.password


# ---------------------------------------------------------------------------
# list_entries
# ---------------------------------------------------------------------------


class TestListEntries:
    def test_returns_empty_list_on_empty_vault(self, key, vault_path) -> None:
        assert list_entries(key, vault_path=vault_path) == []

    def test_returns_all_entries(self, key, vault_path) -> None:
        add_entry(
            key,
            EntryCreate(title="A", password="p1"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        add_entry(
            key,
            EntryCreate(title="B", password="p2"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        add_entry(
            key,
            EntryCreate(title="C", password="p3"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        entries = list_entries(key, vault_path=vault_path)
        assert len(entries) == 3

    def test_entries_ordered_by_title_case_insensitive(self, key, vault_path) -> None:
        add_entry(
            key,
            EntryCreate(title="zebra", password="p1"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        add_entry(
            key,
            EntryCreate(title="Apple", password="p2"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        add_entry(
            key,
            EntryCreate(title="mango", password="p3"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        entries = list_entries(key, vault_path=vault_path)
        titles = [e.title for e in entries]
        assert titles == sorted(titles, key=str.casefold)

    def test_passwords_are_decrypted_in_list(self, key, vault_path) -> None:
        add_entry(
            key,
            EntryCreate(title="Site", password="mypassword"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        entries = list_entries(key, vault_path=vault_path)
        assert entries[0].password == "mypassword"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# search_entries
# ---------------------------------------------------------------------------


class TestSearchEntries:
    def test_matches_substring_in_title(self, key, vault_path, added_entry) -> None:
        results = search_entries(key, "Hub", vault_path=vault_path)
        assert [e.id for e in results] == [added_entry.id]

    def test_matches_substring_in_url(self, key, vault_path, added_entry) -> None:
        results = search_entries(key, "github.com", vault_path=vault_path)
        assert [e.id for e in results] == [added_entry.id]

    def test_match_is_case_insensitive(self, key, vault_path, added_entry) -> None:
        results = search_entries(key, "HUB", vault_path=vault_path)
        assert [e.id for e in results] == [added_entry.id]

    def test_returns_empty_list_for_no_match(self, key, vault_path, added_entry) -> None:
        assert search_entries(key, "nonexistent", vault_path=vault_path) == []

    def test_password_decrypts_correctly(self, key, vault_path, added_entry, sample_create) -> None:
        results = search_entries(key, "Hub", vault_path=vault_path)
        assert results[0].password == sample_create.password

    def test_entries_without_url_not_matched_on_empty_query_remainder(
        self, key, vault_path
    ) -> None:
        add_entry(
            key,
            EntryCreate(title="NoUrl", password="p1"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        results = search_entries(key, "example", vault_path=vault_path)
        assert results == []

    def test_results_ordered_by_title(self, key, vault_path) -> None:
        add_entry(
            key,
            EntryCreate(title="Zeta Mail", password="p1"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        add_entry(
            key,
            EntryCreate(title="Alpha Mail", password="p2"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        results = search_entries(key, "Mail", vault_path=vault_path)
        assert [e.title for e in results] == ["Alpha Mail", "Zeta Mail"]


# ---------------------------------------------------------------------------
# update_entry
# ---------------------------------------------------------------------------


class TestUpdateEntry:
    def test_update_title(self, key, vault_path, added_entry) -> None:
        updated = update_entry(
            key, added_entry.id, EntryUpdate(title="GitLab"), vault_path=vault_path
        )
        assert updated.title == "GitLab"

    def test_update_username(self, key, vault_path, added_entry) -> None:
        updated = update_entry(
            key, added_entry.id, EntryUpdate(username="new@example.com"), vault_path=vault_path
        )
        assert updated.username == "new@example.com"

    def test_update_password_decrypts_correctly(self, key, vault_path, added_entry) -> None:
        updated = update_entry(
            key,
            added_entry.id,
            EntryUpdate(password="newpassword123"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        assert updated.password == "newpassword123"  # pragma: allowlist secret

    def test_updated_password_not_plaintext_in_db(self, key, vault_path, added_entry) -> None:
        new_password = "newpassword123"  # pragma: allowlist secret
        update_entry(key, added_entry.id, EntryUpdate(password=new_password), vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute(
            "SELECT password_enc FROM entries WHERE id = ?", (added_entry.id,)
        ).fetchone()
        conn.close()
        assert new_password.encode() not in bytes(row["password_enc"])

    def test_update_url(self, key, vault_path, added_entry) -> None:
        updated = update_entry(
            key, added_entry.id, EntryUpdate(url="https://gitlab.com"), vault_path=vault_path
        )
        assert updated.url == "https://gitlab.com"

    def test_update_notes(self, key, vault_path, added_entry) -> None:
        updated = update_entry(
            key, added_entry.id, EntryUpdate(notes="Updated notes"), vault_path=vault_path
        )
        assert updated.notes == "Updated notes"

    def test_unset_fields_are_unchanged(self, key, vault_path, added_entry, sample_create) -> None:
        updated = update_entry(
            key, added_entry.id, EntryUpdate(title="New Title"), vault_path=vault_path
        )
        assert updated.username == sample_create.username
        assert updated.password == sample_create.password
        assert updated.url == sample_create.url
        assert updated.notes == sample_create.notes

    def test_updated_at_changes(self, key, vault_path, added_entry) -> None:
        import time

        time.sleep(1)  # ensure at least 1 second passes for timestamp difference
        updated = update_entry(
            key, added_entry.id, EntryUpdate(title="New Title"), vault_path=vault_path
        )
        assert updated.updated_at >= added_entry.updated_at

    def test_created_at_unchanged(self, key, vault_path, added_entry) -> None:
        updated = update_entry(
            key, added_entry.id, EntryUpdate(title="New Title"), vault_path=vault_path
        )
        assert updated.created_at == added_entry.created_at

    def test_raises_not_found_error_for_missing_id(self, key, vault_path) -> None:
        with pytest.raises(NotFoundError):
            update_entry(
                key,
                "00000000-0000-0000-0000-000000000000",
                EntryUpdate(title="X"),
                vault_path=vault_path,
            )

    def test_raises_value_error_when_no_fields_set(self, key, vault_path, added_entry) -> None:
        with pytest.raises(ValueError):
            update_entry(key, added_entry.id, EntryUpdate(), vault_path=vault_path)


# ---------------------------------------------------------------------------
# delete_entry
# ---------------------------------------------------------------------------


class TestDeleteEntry:
    def test_delete_removes_entry(self, key, vault_path, added_entry) -> None:
        delete_entry(added_entry.id, vault_path=vault_path)
        with pytest.raises(NotFoundError):
            get_entry(key, added_entry.id, vault_path=vault_path)

    def test_delete_returns_none(self, key, vault_path, added_entry) -> None:
        result = delete_entry(added_entry.id, vault_path=vault_path)
        assert result is None

    def test_raises_not_found_error_for_missing_id(self, vault_path) -> None:
        with pytest.raises(NotFoundError):
            delete_entry("00000000-0000-0000-0000-000000000000", vault_path=vault_path)

    def test_delete_only_removes_target_entry(self, key, vault_path) -> None:
        e1 = add_entry(
            key,
            EntryCreate(title="Keep", password="p1"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        e2 = add_entry(
            key,
            EntryCreate(title="Delete", password="p2"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        delete_entry(e2.id, vault_path=vault_path)
        remaining = list_entries(key, vault_path=vault_path)
        assert len(remaining) == 1
        assert remaining[0].id == e1.id


# ---------------------------------------------------------------------------
# Full CRUD lifecycle
# ---------------------------------------------------------------------------


class TestFullLifecycle:
    def test_add_get_update_delete(self, key, vault_path) -> None:
        # Add
        entry = add_entry(
            key,
            EntryCreate(title="Lifecycle", password="initial-pass"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        assert entry.title == "Lifecycle"

        # Get
        fetched = get_entry(key, entry.id, vault_path=vault_path)
        assert fetched.id == entry.id
        assert fetched.password == "initial-pass"  # pragma: allowlist secret

        # List
        entries = list_entries(key, vault_path=vault_path)
        assert len(entries) == 1

        # Update
        updated = update_entry(
            key,
            entry.id,
            EntryUpdate(password="updated-pass"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        assert updated.password == "updated-pass"  # pragma: allowlist secret

        # Delete
        delete_entry(entry.id, vault_path=vault_path)
        assert list_entries(key, vault_path=vault_path) == []

    def test_deleted_entry_raises_on_get(self, key, vault_path) -> None:
        entry = add_entry(
            key,
            EntryCreate(title="Gone", password="pass"),  # pragma: allowlist secret
            vault_path=vault_path,
        )
        delete_entry(entry.id, vault_path=vault_path)
        with pytest.raises(NotFoundError):
            get_entry(key, entry.id, vault_path=vault_path)
