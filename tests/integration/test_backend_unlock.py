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


class TestUnlock:
    def test_correct_password_returns_200_with_token(self, initialised_vault: Path) -> None:
        response = client.post("/unlock", json={"master_password": _PASSWORD})
        assert response.status_code == 200
        body = response.json()
        assert "token" in body
        assert isinstance(body["token"], str)
        assert len(body["token"]) > 0

    def test_wrong_password_returns_401(self, initialised_vault: Path) -> None:
        response = client.post("/unlock", json={"master_password": "wrong-password-here"})
        assert response.status_code == 401
        assert "Incorrect master password" in response.json()["detail"]

    def test_vault_not_initialised_returns_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        vault_path = tmp_path / "nonexistent.db"
        monkeypatch.setattr(
            session_module.VaultSession.unlock.__func__, "__defaults__", (vault_path,)
        )
        response = client.post("/unlock", json={"master_password": _PASSWORD})
        assert response.status_code == 400
        assert "Vault not initialised" in response.json()["detail"]


class TestLock:
    def test_valid_token_returns_204(self, initialised_vault: Path) -> None:
        token = client.post("/unlock", json={"master_password": _PASSWORD}).json()["token"]
        response = client.post("/lock", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 204

    def test_revoked_token_is_rejected_with_401(self, initialised_vault: Path) -> None:
        token = client.post("/unlock", json={"master_password": _PASSWORD}).json()["token"]
        first_response = client.post("/lock", headers={"Authorization": f"Bearer {token}"})
        assert first_response.status_code == 204
        # Second lock attempt with the same token must be rejected
        response = client.post("/lock", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_invalid_token_returns_401(self, initialised_vault: Path) -> None:
        response = client.post("/lock", headers={"Authorization": "Bearer not-a-real-token"})
        assert response.status_code == 401

    def test_missing_authorization_header_returns_401(self, initialised_vault: Path) -> None:
        # FastAPI's HTTPBearer returns 401 when the Authorization header is absent entirely.
        # As of FastAPI 0.136+, both missing credentials and invalid credentials return 401.
        response = client.post("/lock")
        assert response.status_code == 401
