"""
CLI entry point. Typer wires each function below to a `pv` subcommand;
the actual logic lives in vault.py and crypto.py — this file is glue.

Master password is always read via getpass (never a CLI flag, which
would leak into shell history / `ps`).

Commands: init, add, get, list, delete, change-password, gen
"""

import getpass
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typer.core import TyperGroup

from cellar.constants import (
    DEFAULT_GENERATED_PASSWORD_LENGTH,
    DEFAULT_VAULT_PATH,
    MINIMUM_MASTER_PASSWORD_LENGTH,
    MSG_ENTRY_ADDED,
    MSG_ENTRY_ALREADY_EXISTS,
    MSG_ENTRY_DELETED,
    MSG_ENTRY_NOT_FOUND,
    MSG_MASTER_PASSWORD_CHANGED,
    MSG_MASTER_PASSWORD_EMPTY,
    MSG_MASTER_PASSWORD_TOO_SHORT,
    MSG_PASSWORDS_DO_NOT_MATCH,
    MSG_VAULT_ALREADY_EXISTS,
    MSG_VAULT_CREATED,
    MSG_VAULT_EMPTY,
    MSG_VAULT_NOT_FOUND,
    MSG_WRONG_MASTER_PASSWORD,
    PROMPT_ENTRY_NOTES,
    PROMPT_ENTRY_URL,
    PROMPT_ENTRY_USERNAME,
    PROMPT_MASTER_PASSWORD,
    PROMPT_MASTER_PASSWORD_CONFIRM,
    PROMPT_MASTER_PASSWORD_NEW,
)
from cellar.crypto import WrongPasswordError
from cellar.generator import (
    PasswordTooShortError,
    generate_password,
)
from cellar.vault import (
    Entry,
    EntryAlreadyExistsError,
    EntryNotFoundError,
    UnlockedVault,
    VaultAlreadyExistsError,
    VaultError,
    VaultFormatError,
    VaultNotFoundError,
)

BANNER = r"""   __    ___  _      _       ____  ____  
  /  ]  /  _]| |    | |     /    ||    \ 
 /  /  /  [_ | |    | |    |  o  ||  D  )
/  /  |    _]| |___ | |___ |     ||    / 
\   \_ |   [_ |     ||     ||  _  ||    \ 
 \    ||     ||     ||     ||  |  ||  .  \
  \___||_____||_____||_____||__|__||__|\_|
"""


class BannerGroup(TyperGroup):
    def format_help(self, ctx, formatter):
        print(BANNER)
        super().format_help(ctx, formatter)

app = typer.Typer(
    name="pv",
    help="cellar: Encrypted password manager (Argon2id + AES-256-GCM)",
    no_args_is_help=True,
    add_completion=False,
    cls=BannerGroup,
)
console = Console()
error_console = Console(stderr=True)  # errors/diagnostics -> stderr, keeps pipes clean


VaultPath = Annotated[
    Path,
    typer.Option(
        "--vault",
        "-v",
        help="Path to the vault file",
        envvar="PV_VAULT",
    ),
]


# =============================================================================
# Helpers
# =============================================================================


def _prompt_master_password(prompt: str = PROMPT_MASTER_PASSWORD) -> str:
    return getpass.getpass(prompt)


def _prompt_master_password_with_confirmation() -> str:
    """
    Prompt twice for a new master password, validating non-empty,
    minimum length, and that both entries match. Exits with code 1
    on any failure — by the time this returns, the password is good.
    """
    first = _prompt_master_password(PROMPT_MASTER_PASSWORD_NEW)

    if not first:
        error_console.print(f"[red]{MSG_MASTER_PASSWORD_EMPTY}[/red]")
        raise typer.Exit(code=1)

    if len(first) < MINIMUM_MASTER_PASSWORD_LENGTH:
        error_console.print(
            f"[red]"
            f"{MSG_MASTER_PASSWORD_TOO_SHORT.format(minimum=MINIMUM_MASTER_PASSWORD_LENGTH)}"
            f"[/red]"
        )
        raise typer.Exit(code=1)

    second = _prompt_master_password(PROMPT_MASTER_PASSWORD_CONFIRM)
    if first != second:
        error_console.print(f"[red]{MSG_PASSWORDS_DO_NOT_MATCH}[/red]")
        raise typer.Exit(code=1)

    return first


def _unlock_or_exit(path: Path, master_password: str) -> UnlockedVault:
    """Open a vault, printing the right message and exiting on any failure."""
    try:
        return UnlockedVault.unlock(path, master_password)
    except VaultNotFoundError:
        error_console.print(f"[red]{MSG_VAULT_NOT_FOUND.format(path=path)}[/red]")
        raise typer.Exit(code=1) from None
    except WrongPasswordError:
        error_console.print(f"[red]{MSG_WRONG_MASTER_PASSWORD}[/red]")
        raise typer.Exit(code=1) from None
    except VaultFormatError as exc:
        error_console.print(f"[red]Vault file is invalid: {exc}[/red]")
        raise typer.Exit(code=1) from None
    except VaultError as exc:
        error_console.print(f"[red]Vault error: {exc}[/red]")
        raise typer.Exit(code=1) from None


def _render_entry(name: str, entry: Entry) -> Panel:
    body_lines = [
        f"[bold]username[/bold]   {entry.username}",
        f"[bold]password[/bold]   {entry.password}",
    ]
    if entry.url:
        body_lines.append(f"[bold]url[/bold]        {entry.url}")
    if entry.notes:
        body_lines.append(f"[bold]notes[/bold]      {entry.notes}")
    body_lines.append(f"[dim]created    {entry.created_at}[/dim]")
    body_lines.append(f"[dim]updated    {entry.updated_at}[/dim]")
    return Panel("\n".join(body_lines), title=name, border_style="cyan")


# =============================================================================
# Commands
# =============================================================================


@app.command()
def init(vault: VaultPath = DEFAULT_VAULT_PATH) -> None:
    """Create a new empty vault at --vault (or PV_VAULT or default path)."""
    # Pre-check avoids prompting for a password we'd throw away; the
    # authoritative check is inside create() to handle a race between
    # this check and the prompt finishing.
    if vault.exists():
        error_console.print(f"[red]{MSG_VAULT_ALREADY_EXISTS.format(path=vault)}[/red]")
        raise typer.Exit(code=1)

    master = _prompt_master_password_with_confirmation()
    try:
        with UnlockedVault.create(vault, master):
            pass
    except VaultAlreadyExistsError:
        error_console.print(f"[red]{MSG_VAULT_ALREADY_EXISTS.format(path=vault)}[/red]")
        raise typer.Exit(code=1) from None

    console.print(f"[green]{MSG_VAULT_CREATED.format(path=vault)}[/green]")


@app.command(name="list")
def list_entries(vault: VaultPath = DEFAULT_VAULT_PATH) -> None:
    """Print every entry name in the vault."""
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        names = unlocked.names()
        if not names:
            console.print(f"[yellow]{MSG_VAULT_EMPTY}[/yellow]")
            return

        table = Table(title=f"Entries in {vault}", show_lines=False)
        table.add_column("name", style="cyan", no_wrap=True)
        table.add_column("username", style="white")
        table.add_column("updated", style="dim")
        for name in names:
            entry = unlocked.entries[name]
            table.add_row(name, entry.username, entry.updated_at)
        console.print(table)


@app.command()
def get(
    name: Annotated[str, typer.Argument(help="Entry name to retrieve")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
) -> None:
    """Show every field of one entry by name."""
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        try:
            entry = unlocked.get_entry(name)
        except EntryNotFoundError:
            error_console.print(f"[red]{MSG_ENTRY_NOT_FOUND.format(name=name)}[/red]")
            raise typer.Exit(code=1) from None
        console.print(_render_entry(name, entry))


@app.command()
def add(
    name: Annotated[str, typer.Argument(help="Entry name (must be unique)")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
    force: Annotated[
        bool, typer.Option("--force", "-f", help="Overwrite if exists")
    ] = False,
    generate: Annotated[
        bool,
        typer.Option(
            "--generate", "-g", help="Generate a random password instead of prompting"
        ),
    ] = False,
    length: Annotated[
        int, typer.Option("--length", "-n", help="Length when --generate is used")
    ] = DEFAULT_GENERATED_PASSWORD_LENGTH,
) -> None:
    """Add (or overwrite with --force) an entry in the vault."""
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        username = input(PROMPT_ENTRY_USERNAME.format(entry=name))

        if generate:
            try:
                password = generate_password(length)
            except PasswordTooShortError as exc:
                error_console.print(f"[red]{exc}[/red]")
                raise typer.Exit(code=1) from None
            console.print(f"[green]Generated password:[/green] {password}")
        else:
            password = _prompt_master_password(f"Password for {name} (hidden): ")

        url = input(PROMPT_ENTRY_URL).strip()
        notes = input(PROMPT_ENTRY_NOTES).strip()

        entry = Entry(username=username, password=password, url=url, notes=notes)

        try:
            unlocked.add_entry(name, entry, force=force)
        except EntryAlreadyExistsError:
            error_console.print(f"[red]{MSG_ENTRY_ALREADY_EXISTS.format(name=name)}[/red]")
            raise typer.Exit(code=1) from None
        except ValueError as exc:
            error_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=1) from None

        unlocked.save()
    console.print(f"[green]{MSG_ENTRY_ADDED.format(name=name)}[/green]")


@app.command()
def delete(
    name: Annotated[str, typer.Argument(help="Entry name to delete")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
) -> None:
    """Remove an entry by name."""
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        try:
            unlocked.delete_entry(name)
        except EntryNotFoundError:
            error_console.print(f"[red]{MSG_ENTRY_NOT_FOUND.format(name=name)}[/red]")
            raise typer.Exit(code=1) from None

        unlocked.save()
    console.print(f"[green]{MSG_ENTRY_DELETED.format(name=name)}[/green]")


@app.command()
def gen(
    length: Annotated[int, typer.Argument(help="Password length")] = (
        DEFAULT_GENERATED_PASSWORD_LENGTH
    ),
    no_symbols: Annotated[
        bool, typer.Option("--no-symbols", help="Letters and digits only")
    ] = False,
    no_digits: Annotated[
        bool, typer.Option("--no-digits", help="Letters and symbols only")
    ] = False,
    no_uppercase: Annotated[
        bool, typer.Option("--no-uppercase", help="No uppercase letters")
    ] = False,
) -> None:
    """Print a fresh random password and exit (no vault required)."""
    try:
        password = generate_password(
            length,
            use_lowercase=True,
            use_uppercase=not no_uppercase,
            use_digits=not no_digits,
            use_symbols=not no_symbols,
        )
    except (PasswordTooShortError, ValueError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    print(password)  # plain print, pipe-friendly: PASSWORD=$(pv gen 32)


@app.command(name="change-password")
def change_password(vault: VaultPath = DEFAULT_VAULT_PATH) -> None:
    """
    Rotate the master password. Unlocks with the old password, derives
    a new salt + key from the new one, and saves — which re-encrypts
    every entry under the new key.
    """
    current = _prompt_master_password("Current master password: ")
    with _unlock_or_exit(vault, current) as unlocked:
        new_password = _prompt_master_password_with_confirmation()
        unlocked.change_master_password(new_password)
        unlocked.save()
    console.print(f"[green]{MSG_MASTER_PASSWORD_CHANGED.format(path=vault)}[/green]")