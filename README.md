# CipherDen

A self-hosted, open-source password manager with a CLI, web UI, and browser extension. All credentials are stored in a locally encrypted SQLite database — nothing leaves your machine.

> **Work in progress.** Everything in this repository — architecture, APIs, file formats, commands, and documentation — is subject to change at any time without notice. Nothing here should be considered stable or final until a 1.0 release is tagged.

> This project is not yet ready for production use. Do not use it to store real credentials.

## What it does

CipherDen gives you three ways to manage your passwords from a single encrypted vault:

- **CLI** — add, get, list, search, delete, and generate passwords from the terminal
- **Web UI** — a React interface for browsing and managing credentials visually
- **Browser extension** — detects login forms and autofills credentials from your local vault

## How it works

Your master password is never stored. On unlock, it is used to derive a 256-bit key via Argon2id, which is held in memory for the session. All password fields are encrypted with AES-256-GCM before being written to disk. The local FastAPI server binds to `127.0.0.1` only and is never exposed to the network.

## Running CipherDen

The CLI talks directly to the vault and requires nothing else running. The web UI and browser extension both require the backend to be running first.

A startup script and a macOS launchd service file will be provided so the backend can be started with a single command or registered to start automatically at login. Linux and Windows support are planned for a future release.

## Project status

| Component | Status |
|-----------|--------|
| Vault core + cryptography | In progress |
| CLI | Planned |
| FastAPI backend | Planned |
| React web UI | Planned |
| Browser extension (MV3) | Planned |

## Tech stack

- **Vault / CLI** — Python, SQLite, `cryptography`, `argon2-cffi`, Typer, Rich
- **Backend** — FastAPI, Pydantic, uvicorn
- **Web UI** — React, TypeScript, Vite, Tailwind CSS, Zustand
- **Browser extension** — TypeScript, Chrome Manifest V3
- **Platform** — macOS (Linux and Windows support planned)

## Getting started

Documentation and installation instructions will be added as each component reaches a stable state. Check back once the vault core and CLI are complete.

## Security

Security is the core concern of this project. If you find a vulnerability, please do not open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

MIT — see [LICENSE](LICENSE) for details.
