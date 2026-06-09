# Security Policy

## Reporting a vulnerability

Please do not report security vulnerabilities through public GitHub issues, pull requests, or discussions. Public disclosure before a fix is in place puts users at risk.

Instead, use GitHub's private vulnerability reporting feature: [Report a vulnerability](https://github.com/smallar1/CipherDen/security/advisories/new)

This keeps the report confidential between you and the maintainer until a fix is in place.

## What to include

A useful report includes:

- A description of the vulnerability and the potential impact
- The component affected (vault, CLI, backend, web UI, or extension)
- Steps to reproduce or a proof of concept
- Any suggested mitigations, if you have them

## What to expect

- A response within 7 days confirming whether the report is accepted
- Credit in the release notes if you would like it, once a fix is shipped

## Scope

Everything in this repository is in scope, with particular interest in:

- Vulnerabilities in the encryption or key derivation implementation
- Authentication bypass on the local API
- Credential leakage through the browser extension
- Vault file exposure or path traversal issues

## Supported versions

As this project is in early development, only the latest commit on `main` is supported. There are no versioned releases yet.
