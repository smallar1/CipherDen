from __future__ import annotations

import string

from fastapi.testclient import TestClient

from cipherden.backend.app import app

client = TestClient(app, raise_server_exceptions=True)

_SYMBOLS = set("!@#$%^&*()-_=+[]{};:,.<>?")


class TestGenerate:
    def test_default_returns_16_char_password(self) -> None:
        response = client.get("/generate")
        assert response.status_code == 200
        assert len(response.json()["password"]) == 16

    def test_respects_length_param(self) -> None:
        response = client.get("/generate", params={"length": 24})
        assert response.status_code == 200
        assert len(response.json()["password"]) == 24

    def test_use_symbols_false_excludes_symbols(self) -> None:
        response = client.get("/generate", params={"length": 32, "use_symbols": False})
        password = response.json()["password"]
        assert not any(c in _SYMBOLS for c in password)

    def test_use_numbers_false_excludes_numbers(self) -> None:
        response = client.get("/generate", params={"length": 32, "use_numbers": False})
        password = response.json()["password"]
        assert not any(c in string.digits for c in password)

    def test_length_below_minimum_is_clamped_to_8(self) -> None:
        response = client.get("/generate", params={"length": 1})
        assert response.status_code == 200
        assert len(response.json()["password"]) == 8

    def test_length_above_maximum_is_clamped_to_128(self) -> None:
        response = client.get("/generate", params={"length": 500})
        assert response.status_code == 200
        assert len(response.json()["password"]) == 128
