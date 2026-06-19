"""
main.py — CipherDen CLI entry point.

Commands:
  cipherden vault init    Initialise a new encrypted vault.
  cipherden add           Add a new credential to the vault.
  cipherden get all       List every credential in the vault.
  cipherden get <title>   Retrieve credential(s) matching a title.
"""

from __future__ import annotations

import typer
from pydantic import ValidationError
from rich.console import Console

from cipherden.vault.init import VaultAlreadyExistsError, vault_init
from cipherden.vault.models import EntryCreate, EntryRead
from cipherden.vault.session import VaultNotInitialisedError, VaultSession, WrongPasswordError
from cipherden.vault.vault import add_entry, get_entries_by_title, list_entries

app = typer.Typer(
    name="cipherden",
    help="CipherDen — self-hosted password manager.",
    no_args_is_help=True,
)

vault_app = typer.Typer(help="Vault management commands.")
app.add_typer(vault_app, name="vault")

console = Console()
err_console = Console(stderr=True)


def _prompt_password() -> str:
    """Prompt for a master password, re-prompting until it meets requirements."""
    while True:
        password = typer.prompt("Master password", hide_input=True)
        if len(password) < 12:
            err_console.print("[red]Error:[/red] Master password must be at least 12 characters.")
            continue
        return password


def _prompt_confirm(password: str) -> None:
    """Prompt for password confirmation, re-prompting until it matches."""
    while True:
        confirm = typer.prompt("Confirm master password", hide_input=True)
        if confirm == password:
            return
        err_console.print("[red]Error:[/red] Passwords do not match. Try again.")


@vault_app.command("init")
def cmd_vault_init() -> None:
    """Initialise a new encrypted vault."""
    password = _prompt_password()
    _prompt_confirm(password)

    try:
        vault_init(password)
        console.print("[green]Vault initialised successfully.[/green]")
    except VaultAlreadyExistsError as exc:
        err_console.print(f"[yellow]Warning:[/yellow] {exc}")
        raise typer.Exit(code=1) from exc


def _unlock_or_exit() -> VaultSession:
    """Prompt for the master password and unlock the vault, or exit(1) on failure."""
    master_password = typer.prompt("Master password", hide_input=True)
    try:
        return VaultSession.unlock(master_password)
    except (VaultNotInitialisedError, WrongPasswordError) as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@app.command("add")
def cmd_add() -> None:
    """Add a new credential to the vault."""
    title = typer.prompt("Title")
    username = typer.prompt("Username", default="", show_default=False)
    password = typer.prompt("Password", hide_input=True)
    url = typer.prompt("URL", default="", show_default=False)
    notes = typer.prompt("Notes", default="", show_default=False)

    try:
        data = EntryCreate(
            title=title,
            username=username,
            password=password,
            url=url or None,
            notes=notes or None,
        )
    except ValidationError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    session = _unlock_or_exit()
    try:
        entry = add_entry(session.key, data)
    finally:
        session.lock()

    console.print("[green]Entry added.[/green]")
    console.print(f"ID: {entry.id}")


def _print_entry(entry: EntryRead) -> None:
    console.print(f"ID: {entry.id}")
    console.print(f"Title: {entry.title}")
    console.print(f"Username: {entry.username}")
    console.print(f"Password: {entry.password}")
    if entry.url:
        console.print(f"URL: {entry.url}")
    if entry.notes:
        console.print(f"Notes: {entry.notes}")


@app.command("get")
def cmd_get(
    identifier: str = typer.Argument(
        ..., help="Entry title to retrieve, or 'all' to list every entry."
    ),
) -> None:
    """Retrieve a credential by title, or every credential with 'all'."""
    is_all = identifier.lower() == "all"
    session = _unlock_or_exit()
    try:
        if is_all:
            entries = list_entries(session.key)
        else:
            entries = get_entries_by_title(session.key, identifier)
    finally:
        session.lock()

    if not entries:
        if is_all:
            console.print("[yellow]Vault is empty.[/yellow]")
            return
        err_console.print(f"[red]Error:[/red] No entry found with title '{identifier}'.")
        raise typer.Exit(code=1)

    for i, entry in enumerate(entries):
        if i > 0:
            console.print()
        _print_entry(entry)
