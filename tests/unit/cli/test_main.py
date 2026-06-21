"""
tests/unit/cli/test_main.py — Unit tests for the CLI vault init, add, get, list,
search, delete, and generate commands.

Uses Typer's CliRunner to invoke commands in-process.
vault_init / add_entry / get_entry / get_entries_by_title / list_entries / search_entries /
delete_entry / generate_password / VaultSession are mocked to isolate CLI logic from
vault logic.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cipherden.cli.main import app
from cipherden.exceptions import NotFoundError
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
# get <id> — happy path
# ---------------------------------------------------------------------------


class TestGetByIdCommand:
    def test_successful_get_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", return_value=_ENTRY),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.id], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0

    def test_get_masks_password_by_default(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", return_value=_ENTRY),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.id], input=f"{_PASSWORD}\n")
        assert _ENTRY.password not in result.output
        assert "********" in result.output
        assert _ENTRY.title in result.output

    def test_get_with_reveal_shows_password(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", return_value=_ENTRY),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.id, "--reveal"], input=f"{_PASSWORD}\n")
        assert _ENTRY.password in result.output

    def test_get_entry_called_with_correct_id(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", return_value=_ENTRY) as mock_get,
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            runner.invoke(app, ["get", _ENTRY.id], input=f"{_PASSWORD}\n")
        assert mock_get.call_args[0][1] == _ENTRY.id

    def test_get_locks_session_afterwards(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", return_value=_ENTRY),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["get", _ENTRY.id], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()


# ---------------------------------------------------------------------------
# get — not found / session failures
# ---------------------------------------------------------------------------


class TestGetCommandErrors:
    def test_not_found_exits_1(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", side_effect=NotFoundError("not found")),
            patch("cipherden.cli.main.get_entries_by_title", return_value=[]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", "nonexistent-id"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 1

    def test_not_found_locks_session(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", side_effect=NotFoundError("not found")),
            patch("cipherden.cli.main.get_entries_by_title", return_value=[]),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["get", "nonexistent-id"], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()

    def test_wrong_master_password_exits_1(self) -> None:
        with patch("cipherden.cli.main.VaultSession") as mock_session_cls:
            mock_session_cls.unlock.side_effect = WrongPasswordError("Incorrect master password.")
            result = runner.invoke(app, ["get", _ENTRY.id], input=f"{_PASSWORD}\n")
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# get — title fallback
# ---------------------------------------------------------------------------


class TestGetByTitleFallback:
    def test_title_lookup_used_when_id_lookup_fails(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", side_effect=NotFoundError("not found")),
            patch(
                "cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY]
            ) as mock_get_by_title,
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0
        assert mock_get_by_title.call_args[0][1] == _ENTRY.title
        assert _ENTRY.title in result.output

    def test_multiple_title_matches_all_printed(self) -> None:
        other = _ENTRY.model_copy(
            update={"id": "22222222-2222-2222-2222-222222222222", "username": "other@example.com"}
        )
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", side_effect=NotFoundError("not found")),
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY, other]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0
        assert result.output.count(_ENTRY.title) == 2
        assert _ENTRY.username in result.output
        assert other.username in result.output

    def test_reveal_applies_to_title_matches(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", side_effect=NotFoundError("not found")),
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", _ENTRY.title, "--reveal"], input=f"{_PASSWORD}\n")
        assert _ENTRY.password in result.output

    def test_not_found_by_either_exits_1(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", side_effect=NotFoundError("not found")),
            patch("cipherden.cli.main.get_entries_by_title", return_value=[]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["get", "nonexistent"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_locks_session_on_title_fallback(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.get_entry", side_effect=NotFoundError("not found")),
            patch("cipherden.cli.main.get_entries_by_title", return_value=[_ENTRY]),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["get", _ENTRY.title], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()


# ---------------------------------------------------------------------------
# list — happy path
# ---------------------------------------------------------------------------


class TestListCommand:
    def test_successful_list_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[_ENTRY]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["list"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0

    def test_list_prints_every_entry_without_password(self) -> None:
        other = _ENTRY.model_copy(
            update={"id": "22222222-2222-2222-2222-222222222222", "title": "GitLab"}
        )
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[_ENTRY, other]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["list"], input=f"{_PASSWORD}\n")
        assert _ENTRY.title in result.output
        assert other.title in result.output
        assert _ENTRY.password not in result.output

    def test_list_on_empty_vault_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["list"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_list_locks_session_afterwards(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.list_entries", return_value=[_ENTRY]),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["list"], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()


# ---------------------------------------------------------------------------
# search — happy path
# ---------------------------------------------------------------------------


class TestSearchCommand:
    def test_successful_search_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.search_entries", return_value=[_ENTRY]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["search", "git"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0

    def test_search_called_with_correct_query(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.search_entries", return_value=[_ENTRY]) as mock_search,
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            runner.invoke(app, ["search", "git"], input=f"{_PASSWORD}\n")
        assert mock_search.call_args[0][1] == "git"

    def test_search_prints_matches_without_password(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.search_entries", return_value=[_ENTRY]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["search", "git"], input=f"{_PASSWORD}\n")
        assert _ENTRY.title in result.output
        assert _ENTRY.password not in result.output

    def test_search_no_matches_exits_0(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.search_entries", return_value=[]),
        ):
            mock_session_cls.unlock.return_value = _mock_unlocked_session()
            result = runner.invoke(app, ["search", "nope"], input=f"{_PASSWORD}\n")
        assert result.exit_code == 0
        assert "no matches" in result.output.lower()

    def test_search_locks_session_afterwards(self) -> None:
        with (
            patch("cipherden.cli.main.VaultSession") as mock_session_cls,
            patch("cipherden.cli.main.search_entries", return_value=[_ENTRY]),
        ):
            mock_session = _mock_unlocked_session()
            mock_session_cls.unlock.return_value = mock_session
            runner.invoke(app, ["search", "git"], input=f"{_PASSWORD}\n")
        mock_session.lock.assert_called_once()


# ---------------------------------------------------------------------------
# delete — happy path
# ---------------------------------------------------------------------------


class TestDeleteCommand:
    def test_confirmed_delete_exits_0(self) -> None:
        with patch("cipherden.cli.main.delete_entry") as mock_delete:
            result = runner.invoke(app, ["delete", _ENTRY.id], input="y\n")
        assert result.exit_code == 0
        mock_delete.assert_called_once_with(_ENTRY.id)

    def test_confirmed_delete_prints_success_message(self) -> None:
        with patch("cipherden.cli.main.delete_entry"):
            result = runner.invoke(app, ["delete", _ENTRY.id], input="y\n")
        assert "deleted" in result.output.lower()

    def test_declined_confirmation_does_not_delete(self) -> None:
        with patch("cipherden.cli.main.delete_entry") as mock_delete:
            result = runner.invoke(app, ["delete", _ENTRY.id], input="n\n")
        assert result.exit_code == 0
        mock_delete.assert_not_called()
        assert "aborted" in result.output.lower()

    def test_delete_nonexistent_id_exits_1(self) -> None:
        with patch("cipherden.cli.main.delete_entry", side_effect=NotFoundError("not found")):
            result = runner.invoke(app, ["delete", "nonexistent-id"], input="y\n")
        assert result.exit_code == 1
        assert "not found" in result.output.lower()


# ---------------------------------------------------------------------------
# generate — happy path
# ---------------------------------------------------------------------------


class TestGenerateCommand:
    def test_default_generate_exits_0(self) -> None:
        with patch(
            "cipherden.cli.main.generate_password", return_value="aB3$xyz9Qw2!mnop"
        ) as mock_gen:
            result = runner.invoke(app, ["generate"])
        assert result.exit_code == 0
        mock_gen.assert_called_once_with(length=16, use_symbols=True, use_numbers=True)

    def test_generate_prints_password(self) -> None:
        with patch("cipherden.cli.main.generate_password", return_value="aB3$xyz9Qw2!mnop"):
            result = runner.invoke(app, ["generate"])
        assert "aB3$xyz9Qw2!mnop" in result.output

    def test_generate_with_length_option(self) -> None:
        with patch("cipherden.cli.main.generate_password", return_value="x" * 32) as mock_gen:
            result = runner.invoke(app, ["generate", "--length", "32"])
        assert result.exit_code == 0
        mock_gen.assert_called_once_with(length=32, use_symbols=True, use_numbers=True)

    def test_generate_no_symbols_flag(self) -> None:
        with patch(
            "cipherden.cli.main.generate_password", return_value="aB3xyz9Qw2mnop12"
        ) as mock_gen:
            result = runner.invoke(app, ["generate", "--no-symbols"])
        assert result.exit_code == 0
        mock_gen.assert_called_once_with(length=16, use_symbols=False, use_numbers=True)

    def test_generate_no_numbers_flag(self) -> None:
        with patch(
            "cipherden.cli.main.generate_password", return_value="aBxyzQwmnopABCDe"
        ) as mock_gen:
            result = runner.invoke(app, ["generate", "--no-numbers"])
        assert result.exit_code == 0
        mock_gen.assert_called_once_with(length=16, use_symbols=True, use_numbers=False)

    def test_generate_invalid_length_exits_1(self) -> None:
        with patch(
            "cipherden.cli.main.generate_password",
            side_effect=ValueError("Password length must be..."),
        ):
            result = runner.invoke(app, ["generate", "--length", "1"])
        assert result.exit_code == 1
