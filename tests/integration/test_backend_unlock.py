from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import cipherden.backend.app as app_module
import cipherden.vault.init as init_module
import cipherden.vault.session as session_module
from cipherden.backend.app import app
from cipherden.backend.session_store import SessionStore
from cipherden.cli.main import app as cli_app

client = TestClient(app, raise_server_exceptions=True)
cli_runner = CliRunner()

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def reset_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the module-level store with a fresh instance before each test."""
    monkeypatch.setattr(app_module, "store", SessionStore())


@pytest.fixture
def initialised_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a real vault in tmp_path and redirect unlock to it."""
    vault_path = tmp_path / "cipherden.db"
    monkeypatch.setattr(init_module.vault_init, "__defaults__", (vault_path,))
    monkeypatch.setattr(session_module.VaultSession.unlock.__func__, "__defaults__", (vault_path,))
    cli_runner.invoke(cli_app, ["vault", "init"], input=f"{_PASSWORD}\n{_PASSWORD}\n")
    return vault_path
