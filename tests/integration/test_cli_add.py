"""
tests/integration/test_cli_add.py — Integration test for `cipherden add`.

Drives the real Typer app (no mocking) against a temporary vault file:
  1. `cipherden vault init` creates the vault.
  2. `cipherden add` saves a new credential and prints its UUID.
  3. The raw SQLite row is verified directly (password stored encrypted,
     never as plaintext).
  4. `cipherden get <id>` retrieves the entry and decrypts the password.
  5. `cipherden list` shows the entry without its password.

The vault/session/CRUD functions all default their `vault_path` argument to
the module-level VAULT_FILE constant, which is bound at import time. Since
the CLI commands never pass a vault_path explicitly, the only way to point
the real CLI at a temp file is to monkeypatch that bound default directly —
monkeypatch.setattr reverts it automatically once the test ends.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

import cipherden.vault.init as init_module
import cipherden.vault.session as session_module
import cipherden.vault.vault as vault_module
from cipherden.cli.main import app

runner = CliRunner()

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
_TITLE = "GitHub"
_USERNAME = "user@example.com"
_ENTRY_PASSWORD = "s3cr3t-entry-password"  # pragma: allowlist secret
_URL = "https://github.com"
_NOTES = "Work account"

_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@pytest.fixture
def tmp_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect every vault_path default to a temp file for this test only."""
    vault_path = tmp_path / "cipherden.db"
    monkeypatch.setattr(init_module.vault_init, "__defaults__", (vault_path,))
    monkeypatch.setattr(session_module.VaultSession.unlock.__func__, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.add_entry, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.get_entry, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.list_entries, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.search_entries, "__defaults__", (vault_path,))
    return vault_path


def _extract_uuid(output: str) -> str:
    match = _UUID_RE.search(output)
    assert match is not None, f"No UUID found in output: {output!r}"
    return match.group(0)


class TestCliAddIntegration:
    def test_add_then_get_round_trip(self, tmp_vault: Path) -> None:
        init_result = runner.invoke(app, ["vault", "init"], input=f"{_PASSWORD}\n{_PASSWORD}\n")
        assert init_result.exit_code == 0

        add_input = f"{_TITLE}\n{_USERNAME}\n{_ENTRY_PASSWORD}\n{_URL}\n{_NOTES}\n{_PASSWORD}\n"
        add_result = runner.invoke(app, ["add"], input=add_input)
        assert add_result.exit_code == 0
        entry_id = _extract_uuid(add_result.output)

        conn = sqlite3.connect(tmp_vault)
        try:
            row = conn.execute("SELECT id FROM entries WHERE id = ?", (entry_id,)).fetchone()
        finally:
            conn.close()
        assert row is not None

        get_result = runner.invoke(app, ["get", entry_id, "--reveal"], input=f"{_PASSWORD}\n")
        assert get_result.exit_code == 0
        assert _ENTRY_PASSWORD in get_result.output
        assert _TITLE in get_result.output

        masked_result = runner.invoke(app, ["get", entry_id], input=f"{_PASSWORD}\n")
        assert masked_result.exit_code == 0
        assert _ENTRY_PASSWORD not in masked_result.output

        list_result = runner.invoke(app, ["list"], input=f"{_PASSWORD}\n")
        assert list_result.exit_code == 0
        assert _TITLE in list_result.output
        assert _ENTRY_PASSWORD not in list_result.output

        search_result = runner.invoke(app, ["search", _TITLE], input=f"{_PASSWORD}\n")
        assert search_result.exit_code == 0
        assert _TITLE in search_result.output

    def test_password_not_stored_as_plaintext_in_raw_db(self, tmp_vault: Path) -> None:
        runner.invoke(app, ["vault", "init"], input=f"{_PASSWORD}\n{_PASSWORD}\n")
        add_input = f"{_TITLE}\n{_USERNAME}\n{_ENTRY_PASSWORD}\n{_URL}\n{_NOTES}\n{_PASSWORD}\n"
        add_result = runner.invoke(app, ["add"], input=add_input)
        entry_id = _extract_uuid(add_result.output)

        conn = sqlite3.connect(tmp_vault)
        try:
            row = conn.execute(
                "SELECT title, username, password_enc, url, notes FROM entries WHERE id = ?",
                (entry_id,),
            ).fetchone()
        finally:
            conn.close()

        title, username, password_enc, url, notes = row
        assert title == _TITLE
        assert username == _USERNAME
        assert url == _URL
        assert notes == _NOTES
        assert _ENTRY_PASSWORD.encode() not in bytes(password_enc)
