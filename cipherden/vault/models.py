"""
models.py — Pydantic models for vault entry CRUD.

These models define the shape of data flowing in and out of the vault layer.
They never hold a decrypted password at rest — EntryRead.password is the
decrypted plaintext returned only within a live unlocked session.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field, field_validator


class EntryCreate(BaseModel):
    """Input schema for adding a new vault entry."""

    title: str = Field(..., min_length=1, max_length=255)
    username: str = Field(default="", max_length=255)
    password: str = Field(..., min_length=1)
    url: str | None = Field(default=None, max_length=2048)
    notes: str | None = Field(default=None, max_length=10_000)


class EntryRead(BaseModel):
    """Output schema for a fully decrypted vault entry."""

    id: str
    title: str
    username: str
    password: str  # decrypted plaintext — only exists in-memory during session
    url: str | None
    notes: str | None
    created_at: str
    updated_at: str

    @field_validator("id")
    @classmethod
    def _validate_uuid(cls, v: str) -> str:
        uuid.UUID(v)  # raises ValueError if malformed
        return v


class EntryUpdate(BaseModel):
    """Partial-update schema — all fields optional, at least one must be set."""

    title: str | None = Field(default=None, min_length=1, max_length=255)
    username: str | None = Field(default=None, max_length=255)
    password: str | None = Field(default=None, min_length=1)
    url: str | None = Field(default=None, max_length=2048)
    notes: str | None = Field(default=None, max_length=10_000)

    def has_updates(self) -> bool:
        """Return True if at least one field is set."""
        return any(v is not None for v in self.model_dump().values())
