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
        found: VaultSession | None = None
        for stored_token, session in self._sessions.items():
            if hmac.compare_digest(stored_token, token):
                found = session
        # No early exit — always iterate all tokens to avoid leaking
        # whether a prefix matched via timing.
        return found

    def revoke(self, token: str) -> bool:
        matched_key = None
        for stored_token in self._sessions:
            if hmac.compare_digest(stored_token, token):
                matched_key = stored_token
        # No early exit — always scan all tokens to avoid timing leaks.
        if matched_key is None:
            return False
        session = self._sessions.pop(matched_key)
        if not session.is_locked:
            session.lock()
        return True

    def revoke_all(self) -> None:
        for session in self._sessions.values():
            if not session.is_locked:
                session.lock()
        self._sessions.clear()
