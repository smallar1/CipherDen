from __future__ import annotations

import hmac
import secrets

from cipherden.vault.session import VaultSession


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, VaultSession] = {}

    def create(self, session: VaultSession) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = session
        return token

    def get(self, token: str) -> VaultSession | None:
        for stored_token, session in self._sessions.items():
            if hmac.compare_digest(stored_token, token):
                return session
        return None

    def revoke(self, token: str) -> bool:
        session = self._sessions.pop(token, None)
        if session is None:
            return False
        if not session.is_locked:
            session.lock()
        return True

    def revoke_all(self) -> None:
        for session in self._sessions.values():
            if not session.is_locked:
                session.lock()
        self._sessions.clear()
