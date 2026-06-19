"""
main.py — CipherDen CLI entry point.

Commands:
  cipherden vault init      Initialise a new encrypted vault.
  cipherden add             Add a new credential to the vault.
  cipherden get <id|title>  Retrieve a credential by ID or title (password masked unless --reveal).
  cipherden list            List every credential in the vault.
  cipherden search <query>  Search credentials by title or URL.
"""

from __future__ import annotations

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from cipherden.exceptions import NotFoundError
from cipherden.vault.init import VaultAlreadyExistsError, vault_init
from cipherden.vault.models import EntryCreate, EntryRead
from cipherden.vault.session import VaultNotInitialisedError, VaultSession, WrongPasswordError
from cipherden.vault.vault import (
    add_entry,
    get_entries_by_title,
    get_entry,
    list_entries,
    search_entries,
)

_MASKED_PASSWORD = "********"  # noqa: S105

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


def _print_entry_table(entry: EntryRead, *, reveal: bool) -> None:
    table = Table(show_header=False)
    table.add_row("ID", entry.id)
    table.add_row("Title", entry.title)
    table.add_row("Username", entry.username)
    table.add_row("Password", entry.password if reveal else _MASKED_PASSWORD)
    if entry.url:
        table.add_row("URL", entry.url)
    if entry.notes:
        table.add_row("Notes", entry.notes)
    console.print(table)


def _print_entries_table(entries: list[EntryRead]) -> None:
    table = Table()
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Username")
    table.add_column("URL")
    for entry in entries:
        table.add_row(entry.id, entry.title, entry.username, entry.url or "")
    console.print(table)


@app.command("get")
def cmd_get(
    identifier: str = typer.Argument(..., help="ID or title of the entry to retrieve."),
    reveal: bool = typer.Option(
        False, "--reveal", help="Show the password in plaintext instead of masking it."
    ),
) -> None:
    """Retrieve a credential by ID or title."""
    session = _unlock_or_exit()
    try:
        try:
            entries = [get_entry(session.key, identifier)]
        except NotFoundError:
            entries = get_entries_by_title(session.key, identifier)
            if not entries:
                err_console.print(f"[red]Error:[/red] Entry '{identifier}' not found.")
                raise typer.Exit(code=1) from None
    finally:
        session.lock()

    for entry in entries:
        _print_entry_table(entry, reveal=reveal)


@app.command("list")
def cmd_list() -> None:
    """List every credential in the vault."""
    session = _unlock_or_exit()
    try:
        entries = list_entries(session.key)
    finally:
        session.lock()

    if not entries:
        console.print("[yellow]Vault is empty.[/yellow]")
        return

    _print_entries_table(entries)


@app.command("search")
def cmd_search(
    query: str = typer.Argument(..., help="Text to search for in entry titles and URLs."),
) -> None:
    """Search credentials by title or URL."""
    session = _unlock_or_exit()
    try:
        entries = search_entries(session.key, query)
    finally:
        session.lock()

    if not entries:
        console.print(f"[yellow]No matches found for '{query}'.[/yellow]")
        return

    _print_entries_table(entries)
