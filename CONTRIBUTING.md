# Contributing to CipherDen

Thanks for your interest in contributing. CipherDen is not accepting external contributions until v1.0 is released. The architecture, APIs, and file formats are still being established and the codebase is changing frequently.

Feel free to open issues to report bugs or suggest ideas — those are welcome at any stage. Pull requests from external contributors will not be reviewed or merged until v1.0.

## Before you start

Open an issue first. Whether it's a bug, a feature idea, or a refactor, start a conversation before writing code. This avoids situations where work gets done that doesn't align with the current direction of the project.

If you're picking up an existing issue, leave a comment saying you're working on it so there's no duplication.

## What's in scope right now

The current focus is building out the core backlog in order: vault core, CLI, backend API, web UI, and browser extension. Contributions that align with the active sprint are most likely to be reviewed and merged quickly.

Out of scope for now:
- Linux and Windows support
- Mobile clients
- Cloud sync or remote vault storage
- Any changes to the encryption scheme without a prior discussion and ADR

## Development setup

Documentation and setup instructions will be added once the vault core and CLI are stable. Check back after Sprint 1.

## Pull requests

- Keep PRs focused — one concern per PR
- Write tests for anything you add or change
- Make sure CI passes before requesting review
- Update relevant documentation if your change affects behaviour
- If your change introduces a significant technical decision, note it in the PR description — it may warrant an ADR

## Security

If you find a security vulnerability, do not open a public issue. Follow the instructions in [SECURITY.md](SECURITY.md).

## Code style

- Python: `ruff` for linting and formatting
- TypeScript: `eslint` and `prettier`

Pre-commit hooks enforce both. Run `pre-commit install` after cloning to set them up.

## Commit messages

Keep them short and descriptive. Reference the Jira ticket or GitHub issue where relevant, e.g. `fix: correct nonce handling in encrypt() — KC-003`.

## License

By contributing, you agree that your contributions will be licensed under the same MIT license that covers this project.