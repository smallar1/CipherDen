"""
tests/unit/cli/test_main.py — Unit tests for the CLI vault init, add, and get commands.

Uses Typer's CliRunner to invoke commands in-process.
vault_init / add_entry / get_entries_by_title / list_entries / VaultSession are
mocked to isolate CLI logic from vault logic.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cipherden.cli.main import app
from cipherden.vault.init import VaultAlreadyExistsError
from cipherden.vault.models import EntryRead
from cipherden.vault.session import VaultNotInitialisedError, WrongPasswordError

runner = CliRunner()

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
_SHORT = "short"
_CONFIRM = f"{_PASSWORD}\n{_PASSWORD}\n"

_ENTRY = EntryRead(
    id="11111111-1111-1111-1111-111111111111",
    title="GitHub",
    username="user@example.com",
    password="s3cr3t-password",  # pragma: allowlist secret
    url="https://github.com",
    notes="Work account",
    created_at="2025-01-01T00:00:00Z",
    updated_at="2025-01-01T00:00:00Z",
)

_ADD_INPUT = (
    "\n".join([_ENTRY.title, _ENTRY.username, _ENTRY.password, _ENTRY.url, _ENTRY.notes, _PASSWORD])
    + "\n"
)


def _mock_unlocked_session() -> MagicMock:
    session = MagicMock()
    session.key = bytearray(32)
    return session


# ---------------------------------------------------------------------------
# vault init — happy path
# ---------------------------------------------------------------------------


class TestVaultInitCommand:
    def test_successful_init_exits_0(self) -> None:
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32):
            result = runner.invoke(app, ["vault", "init"], input=_CONFIRM)
        assert result.exit_code == 0

    def test_successful_init_prints_success_message(self) -> None:
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32):
            result = runner.invoke(app, ["vault", "init"], input=_CONFIRM)
        assert "successfully" in result.output.lower()

    def test_vault_init_called_once(self) -> None:
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32) as mock:
            runner.invoke(app, ["vault", "init"], input=_CONFIRM)
        mock.assert_called_once()

    def test_vault_init_called_with_correct_password(self) -> None:
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32) as mock:
            runner.invoke(app, ["vault", "init"], input=_CONFIRM)
        assert mock.call_args[0][0] == _PASSWORD


# ---------------------------------------------------------------------------
# vault init — short password re-prompts then succeeds
# ---------------------------------------------------------------------------


class TestVaultInitPasswordTooShort:
    def test_short_password_shows_error(self) -> None:
        # First attempt too short, second attempt valid with confirmation.
        input_seq = f"{_SHORT}\n{_PASSWORD}\n{_PASSWORD}\n"
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32):
            result = runner.invoke(app, ["vault", "init"], input=input_seq)
        assert "12 characters" in result.output

    def test_succeeds_after_short_then_valid_password(self) -> None:
        input_seq = f"{_SHORT}\n{_PASSWORD}\n{_PASSWORD}\n"
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32):
            result = runner.invoke(app, ["vault", "init"], input=input_seq)
        assert result.exit_code == 0

    def test_vault_init_not_called_until_valid_password(self) -> None:
        input_seq = f"{_SHORT}\n{_PASSWORD}\n{_PASSWORD}\n"
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32) as mock:
            runner.invoke(app, ["vault", "init"], input=input_seq)
        mock.assert_called_once()


# ---------------------------------------------------------------------------
# vault init — confirmation mismatch re-prompts then succeeds
# ---------------------------------------------------------------------------


class TestVaultInitPasswordMismatch:
    def test_mismatch_shows_error(self) -> None:
        # First confirmation wrong, second correct.
        input_seq = f"{_PASSWORD}\ndifferent-password-xyz\n{_PASSWORD}\n"
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32):
            result = runner.invoke(app, ["vault", "init"], input=input_seq)
        assert "do not match" in result.output.lower()

    def test_succeeds_after_mismatch_then_correct_confirm(self) -> None:
        input_seq = f"{_PASSWORD}\ndifferent-password-xyz\n{_PASSWORD}\n"
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32):
            result = runner.invoke(app, ["vault", "init"], input=input_seq)
        assert result.exit_code == 0

    def test_vault_init_called_once_after_mismatch_retry(self) -> None:
        input_seq = f"{_PASSWORD}\ndifferent-password-xyz\n{_PASSWORD}\n"
        with patch("cipherden.cli.main.vault_init", return_value=b"\x00" * 32) as mock:
            runner.invoke(app, ["vault", "init"], input=input_seq)
        mock.assert_called_once()


# ---------------------------------------------------------------------------
# vault init — vault already exists
# ---------------------------------------------------------------------------


class TestVaultInitAlreadyExists:
    def test_exits_1_when_vault_exists(self) -> None:
        err = VaultAlreadyExistsError("already exists")
        with patch("cipherden.cli.main.vault_init", side_effect=err):
            result = runner.invoke(app, ["vault", "init"], input=_CONFIRM)
        assert result.exit_code == 1

    def test_warning_message_shown_when_vault_exists(self) -> None:
        err = VaultAlreadyExistsError("already exists")
        with patch("cipherden.cli.main.vault_init", side_effect=err):
            result = runner.invoke(app, ["vault", "init"], input=_CONFIRM)
        assert "already" in result.output.lower()


# ---------------------------------------------------------------------------
# add — happy path
# ---------------------------------------------------------------------------


class TestAddCommand:
    def test_successful_add_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.add_entry", return_value=_ENTRY),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["add"], input=_ADD_INPUT)
        assert result.exit_code == 0

    def test_successful_add_prints_entry_id(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.add_entry", return_value=_ENTRY),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["add"], input=_ADD_INPUT)
        assert _ENTRY.id in result.output

    def test_add_entry_called_with_correct_data(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.add_entry", return_value=_ENTRY) as mock_add,
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            runner.invoke(app, ["add"], input=_ADD_INPUT)
        data = mock_add.call_args[0][1]
        assert data.title == _ENTRY.title
        assert data.username == _ENTRY.username
        assert data.password == _ENTRY.password
        assert data.url == _ENTRY.url
        assert data.notes == _ENTRY.notes

    def test_add_unlocks_with_master_password(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.add_entry", return_value=_ENTRY),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            runner.invoke(app, ["add"], input=_ADD_INPUT)
        assert mock_session_cls.unlock.call_args[0][0] == _PASSWORD

    def test_add_locks_session_afterwards(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.add_entry", return_value=_ENTRY),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["add"], input=_ADD_INPUT)
        mock_session.lock.assert_called_once()


# ---------------------------------------------------------------------------
# add — blank title rejected
# ---------------------------------------------------------------------------


class TestAddCommandValidation:
    def test_blank_title_exits_1(self) -> None:
        blank_title_input = f"\n{_ENTRY.username}\n{_ENTRY.password}\n\n\n"
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.add_entry", return_value=_ENTRY),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["add"], input=blank_title_input)
        assert result.exit_code == 1

    def test_blank_title_does_not_unlock_vault(self) -> None:
        blank_title_input = f"\n{_ENTRY.username}\n{_ENTRY.password}\n\n\n"
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.add_entry", return_value=_ENTRY),
        ):
            result = runner.invoke(app, ["add"], input=blank_title_input)
        mock_session_cls.unlock.assert_not_called()
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# add — vault session failures
# ---------------------------------------------------------------------------


class TestAddCommandSessionErrors:
    def test_wrong_master_password_exits_1(self) -> None:
        with patch("cipherden.cli.main.VaultSession") as mock_session_cls:
            mock_session_cls.unlock.side_effect = WrongPasswordError("Incorrect master password.")
            result = runner.invoke(app, ["add"], input=_ADD_INPUT)
        assert result.exit_code == 1

    def test_uninitialised_vault_exits_1(self) -> None:
        with patch("cipherden.cli.main.VaultSession") as mock_session_cls:
            mock_session_cls.unlock.side_effect = VaultNotInitialisedError("No vault found.")
            result = runner.invoke(app, ["add"], input=_ADD_INPUT)
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# get <title> — happy path
# ---------------------------------------------------------------------------


class TestGetByTitleCommand:
    def test_successful_get_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0

    def test_get_prints_decrypted_password(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        assert _ENTRY.password in result.output
        assert _ENTRY.title in result.output

    def test_get_entries_by_title_called_with_correct_title(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY]) as mock_get,
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        assert mock_get.call_args[0][1] == _ENTRY.title

    def test_get_locks_session_afterwards(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY]),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()

    def test_multiple_matches_prints_all(self) -> None:
        other = _ENTRY.model_copy(update={"id": "22222222-2222-2222-2222-222222222222"})
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY, other]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        assert result.output.count(_ENTRY.title) == 2


# ---------------------------------------------------------------------------
# get all — happy path
# ---------------------------------------------------------------------------


class TestGetAllCommand:
    def test_successful_get_all_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[_ENTRY]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", "all"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0

    def test_get_all_is_case_insensitive(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[_ENTRY]) as mock_list,
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            runner.invoke(app, ["get", "ALL"], input=f"{_PASSWORD}\n")
        mock_list.assert_called_once()

    def test_get_all_prints_every_entry(self) -> None:
        other = _ENTRY.model_copy(
            update={"id": "22222222-2222-2222-2222-222222222222", "title": "GitLab"}
        )
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[_ENTRY, other]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", "all"], input=f"{_PASSWORD}\n")
        assert _ENTRY.title in result.output
        assert other.title in result.output

    def test_get_all_on_empty_vault_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", "all"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_get_all_locks_session_afterwards(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[_ENTRY]),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["get", "all"], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()


# ---------------------------------------------------------------------------
# get — not found / session failures
# ---------------------------------------------------------------------------


class TestGetCommandErrors:
    def test_not_found_exits_1(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entries_by_title", return_value=[]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", "Nonexistent"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 1

    def test_not_found_locks_session(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entries_by_title", return_value=[]),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["get", "Nonexistent"], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()

    def test_wrong_master_password_exits_1(self) -> None:
        with patch("cipherden.cli.main.VaultSession") as mock_session_cls:
            mock_session_cls.unlock.side_effect = WrongPasswordError("Incorrect master password.")
            result = runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        assert result.exit_code == 1
