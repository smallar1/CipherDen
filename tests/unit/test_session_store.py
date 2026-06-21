from __future__ import annotations

from cipherden.backend.session_store import SessionStore
from cipherden.vault.session import VaultSession


def _fake_session() -> VaultSession:
    """Construct a VaultSession with a 32-byte fake key — no vault file required."""
    return VaultSession(bytearray(32))


class TestSessionStore:
    def test_create_returns_string_token(self) -> None:
        store = SessionStore()
        token = store.create(_fake_session())
        assert isinstance(token, str)
        assert len(token) > 0

    def test_get_returns_session_for_valid_token(self) -> None:
        store = SessionStore()
        session = _fake_session()
        token = store.create(session)
        assert store.get(token) is session

    def test_get_returns_none_for_unknown_token(self) -> None:
        store = SessionStore()
        assert store.get("not-a-real-token") is None

    def test_get_returns_none_after_revoke(self) -> None:
        store = SessionStore()
        session = _fake_session()
        token = store.create(session)
        store.revoke(token)
        assert store.get(token) is None

    def test_revoke_locks_the_session(self) -> None:
        store = SessionStore()
        session = _fake_session()
        token = store.create(session)
        store.revoke(token)
        assert session.is_locked

    def test_revoke_returns_true_for_existing_token(self) -> None:
        store = SessionStore()
        token = store.create(_fake_session())
        assert store.revoke(token) is True

    def test_revoke_returns_false_for_unknown_token(self) -> None:
        store = SessionStore()
        assert store.revoke("ghost-token") is False

    def test_revoke_all_locks_every_session(self) -> None:
        store = SessionStore()
        sessions = [_fake_session() for _ in range(3)]
        for s in sessions:
            store.create(s)
        store.revoke_all()
        assert all(s.is_locked for s in sessions)

    def test_revoke_all_clears_store(self) -> None:
        store = SessionStore()
        token = store.create(_fake_session())
        store.revoke_all()
        assert store.get(token) is None
