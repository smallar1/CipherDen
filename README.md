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
| Vault core + cryptography | Done |
| CLI | Done |
| FastAPI backend | In progress |
| React web UI | In progress |
| Browser extension (MV3) | Planned |

## Tech stack

- **Vault / CLI** — Python, SQLite, `cryptography`, `argon2-cffi`, Typer, Rich
- **Backend** — FastAPI, Pydantic, uvicorn
- **Web UI** — React, TypeScript, Vite (styling and state-management libraries not yet adopted — current pages are intentionally unstyled stand-ins)
- **Browser extension** — TypeScript, Chrome Manifest V3
- **Platform** — macOS (Linux and Windows support planned)

## Getting started

The vault core and CLI are stable enough to use locally. Requires Python 3.14.5 or later.

```bash
git clone https://github.com/smallar1/CipherDen.git
cd CipherDen
pip install -e .
```

Initialise a vault, then manage credentials from the terminal:

```bash
cipherden vault init           # set a master password
cipherden add                  # add a credential
cipherden get <id|title>       # retrieve a credential (password masked unless --reveal)
cipherden list                 # list every credential
cipherden search <query>       # search by title or URL
cipherden delete <id>          # delete a credential (with confirmation)
cipherden generate --length 20 # generate a random password
```

Installation instructions for the web UI and browser extension will be added once those components are stable.

## Security

Security is the core concern of this project. If you find a vulnerability, please do not open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## License

MIT — see [LICENSE](LICENSE) for details.
