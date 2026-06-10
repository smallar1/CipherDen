"""
main.py — CipherDen CLI entry point.

Commands:
  cipherden vault init    Initialise a new encrypted vault.
"""

from __future__ import annotations

import typer
from rich.console import Console

from cipherden.vault.init import VaultAlreadyExistsError, vault_init

app = typer.Typer(
    name="cipherden",
    help="CipherDen — self-hosted password manager.",
    no_args_is_help=True,
)

vault_app = typer.Typer(help="Vault management commands.")
app.add_typer(vault_app, name="vault")

console = Console()
err_console = Console(stderr=True)


@vault_app.command("init")
def cmd_vault_init() -> None:
    """Initialise a new encrypted vault."""
    password = typer.prompt("Master password", hide_input=True)
    confirm = typer.prompt("Confirm master password", hide_input=True)

    if password != confirm:
        err_console.print("[red]Error:[/red] Passwords do not match.")
        raise typer.Exit(code=1)

    if len(password) < 12:
        err_console.print("[red]Error:[/red] Master password must be at least 12 characters.")
        raise typer.Exit(code=1)

    try:
        vault_init(password)
        console.print("[green]Vault initialised successfully.[/green]")
    except VaultAlreadyExistsError as exc:
        err_console.print(f"[yellow]Warning:[/yellow] {exc}")
        raise typer.Exit(code=1) from exc
