"""
tests/unit/cli/test_main.py — Unit tests for the CLI vault init command.

Uses Typer's CliRunner to invoke commands in-process without spawning
a subprocess. The actual vault_init function is mocked to isolate CLI
logic from vault logic (which is tested in test_init.py).
"""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from cipherden.cli.main import app
from cipherden.vault.init import VaultAlreadyExistsError

runner = CliRunner()

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
_CONFIRM = f"{_PASSWORD}\n{_PASSWORD}\n"
_MISMATCH = f"{_PASSWORD}\ndifferent-password-xyz\n"
_SHORT = "short\nshort\n"


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
# vault init — password mismatch
# ---------------------------------------------------------------------------


class TestVaultInitPasswordMismatch:
    def test_exits_1_on_mismatch(self) -> None:
        with patch("cipherden.cli.main.vault_init"):
            result = runner.invoke(app, ["vault", "init"], input=_MISMATCH)
        assert result.exit_code == 1

    def test_vault_init_not_called_on_mismatch(self) -> None:
        with patch("cipherden.cli.main.vault_init") as mock:
            runner.invoke(app, ["vault", "init"], input=_MISMATCH)
        mock.assert_not_called()

    def test_error_message_shown_on_mismatch(self) -> None:
        with patch("cipherden.cli.main.vault_init"):
            result = runner.invoke(app, ["vault", "init"], input=_MISMATCH)
        assert "do not match" in result.output.lower()


# ---------------------------------------------------------------------------
# vault init — password too short
# ---------------------------------------------------------------------------


class TestVaultInitPasswordTooShort:
    def test_exits_1_on_short_password(self) -> None:
        with patch("cipherden.cli.main.vault_init"):
            result = runner.invoke(app, ["vault", "init"], input=_SHORT)
        assert result.exit_code == 1

    def test_vault_init_not_called_on_short_password(self) -> None:
        with patch("cipherden.cli.main.vault_init") as mock:
            runner.invoke(app, ["vault", "init"], input=_SHORT)
        mock.assert_not_called()

    def test_error_message_shown_on_short_password(self) -> None:
        with patch("cipherden.cli.main.vault_init"):
            result = runner.invoke(app, ["vault", "init"], input=_SHORT)
        assert "12 characters" in result.output


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
