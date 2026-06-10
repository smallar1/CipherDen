"""
tests/unit/cli/test_main.py — Unit tests for the CLI vault init command.

Uses Typer's CliRunner to invoke commands in-process.
vault_init is mocked to isolate CLI logic from vault logic.
"""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from cipherden.cli.main import app
from cipherden.vault.init import VaultAlreadyExistsError

runner = CliRunner()

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
_SHORT = "short"
_CONFIRM = f"{_PASSWORD}\n{_PASSWORD}\n"


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
