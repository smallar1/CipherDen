# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Setup

```bash
pip install -e ".[dev]"
pre-commit install
```

## Commands

```bash
# Run all tests
pytest

# Run a single test
pytest tests/integration/test_cli_add.py::TestCliAddIntegration::test_add_then_get_round_trip

# Run tests with coverage (must meet 85% threshold)
pytest --cov

# Lint (with auto-fix)
ruff check --fix .

# Format
ruff format .

# Lint + format in one pass (what pre-commit runs)
pre-commit run --all-files

# Run the CLI
cipherden --help
```

## Architecture

CipherDen is a local-only password manager. All credentials are stored in a SQLite database at `~/.cipherden/cipherden.db`. Nothing leaves the machine.

### Vault layer (`cipherden/vault/`)

The core of the project. Called directly by the CLI and will be wrapped by the FastAPI backend.

- **`crypto.py`** — Argon2id key derivation and AES-256-GCM encrypt/decrypt. The derived key is a `bytearray` so it can be zeroed on lock. Never stored to disk.
- **`db.py`** — SQLite connection factory (`open_db`) and schema migrations. Migrations are numbered tuples in `_MIGRATIONS`; **never edit an existing migration — always add a new one**.
- **`init.py`** — `vault_init()` creates `~/.cipherden/cipherden.db`, writes the Argon2id salt + params + encrypted sentinel to `vault_config`. `VAULT_FILE` is the module-level default path.
- **`session.py`** — `VaultSession` holds the in-memory key for an unlocked vault. Call `session.lock()` (or use it as a context manager) to zero the key buffer. CLI commands always call `session.lock()` in a `finally` block.
- **`models.py`** — Pydantic models: `EntryCreate` (input), `EntryRead` (decrypted output), `EntryUpdate` (partial update).
- **`vault.py`** — CRUD: `add_entry`, `get_entry`, `get_entries_by_title`, `list_entries`, `search_entries`, `update_entry`, `delete_entry`. AAD for each password field is `f"{entry_id}:password".encode()` — this binds ciphertext to its row and prevents transplant attacks.

### CLI (`cipherden/cli/main.py`)

Typer app with a `vault` sub-app (`cipherden vault init`). Commands prompt interactively; none accept `--vault-path` flags. The vault path is controlled by the module-level `VAULT_FILE` default on `vault_init`, `VaultSession.unlock`, and each CRUD function.

### Backend (`cipherden/backend/`)

FastAPI — currently a stub. Planned to wrap the vault layer and serve the web UI and browser extension over `127.0.0.1` only.

## Testing

Integration tests drive the real Typer CLI via `typer.testing.CliRunner` with no mocking. Because CLI commands don't accept `vault_path` arguments, tests **monkeypatch the `__defaults__` of each vault function** to point at a `tmp_path` fixture. See the `tmp_vault` fixture in `tests/integration/test_cli_add.py` for the pattern.

`pytest-asyncio` is configured with `asyncio_mode = "auto"` — no `@pytest.mark.asyncio` decorator needed on async tests.

## Constraints and gotchas

- **ruff is pinned `<0.15`** — 0.15.x mis-formats parenthesized except-tuples under `py314`. Do not upgrade.
- **`detect-secrets` pre-commit hook** — fires on any string that looks like a credential. Use `# pragma: allowlist secret` inline to suppress false positives in tests.
- **Argon2id params are stored in `vault_config`** so future unlocks use the exact params from init time, even if `crypto.py` defaults change later.
- **Encryption format**: `nonce (12 bytes) || ciphertext+tag`. AAD must match exactly between encrypt and decrypt calls or authentication fails.
- **Branch workflow**: all work happens on `KC-NNN` feature branches off `main`. PRs reference the Jira ticket (`KC-NNN`).
- **Commit messages**: short and descriptive; reference the ticket where relevant (e.g. `fix: correct nonce handling — KC-003`). No `Co-Authored-By` trailers.
