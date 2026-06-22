from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import cipherden.backend.app as app_module
import cipherden.vault.init as init_module
import cipherden.vault.session as session_module
import cipherden.vault.vault as vault_module
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
    """Create a real vault in tmp_path and redirect all vault functions to it."""
    vault_path = tmp_path / "cipherden.db"
    monkeypatch.setattr(init_module.vault_init, "__defaults__", (vault_path,))
    monkeypatch.setattr(session_module.VaultSession.unlock.__func__, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.add_entry, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.get_entry, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.list_entries, "__defaults__", (vault_path,))
    monkeypatch.setattr(vault_module.search_entries, "__defaults__", (vault_path,))
    cli_runner.invoke(cli_app, ["vault", "init"], input=f"{_PASSWORD}\n{_PASSWORD}\n")
    return vault_path


def _unlock(vault_path: Path) -> str:
    response = client.post("/unlock", json={"master_password": _PASSWORD})
    return response.json()["token"]


class TestCreateEntry:
    def test_valid_token_returns_201_with_entry(self, initialised_vault: Path) -> None:
        token = _unlock(initialised_vault)
        response = client.post(
            "/entries",
            json={
                "title": "Example",
                "username": "me",
                "password": "xK9!mPq2vT@nL8wZ",  # pragma: allowlist secret
            },
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 201
        body = response.json()
        assert body["title"] == "Example"
        assert body["username"] == "me"
        assert body["password"] == "xK9!mPq2vT@nL8wZ"  # pragma: allowlist secret
        assert "id" in body

    def test_invalid_token_returns_401(self, initialised_vault: Path) -> None:
        response = client.post(
            "/entries",
            json={"title": "Example", "username": "", "password": "x"},
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert response.status_code == 401

    def test_missing_authorization_header_returns_401(self, initialised_vault: Path) -> None:
        response = client.post(
            "/entries",
            json={"title": "Example", "username": "", "password": "x"},
        )
        assert response.status_code == 401
