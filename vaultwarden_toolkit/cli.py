"""
vaultwarden_toolkit.cli
========================

The interactive terminal front-end. Run via the ``vaultwarden-toolkit``
console script (see pyproject.toml) or ``python -m vaultwarden_toolkit``.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from . import crypto, db, exporters

console = Console()


# ---------------------------------------------------------------------------
# Entry point / argument parsing
# ---------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vaultwarden-toolkit",
        description=(
            "Offline toolkit for a local Vaultwarden db.sqlite3 file: decrypt "
            "and export a user's vault, and manage/remove 2FA for account "
            "recovery. Requires no running Vaultwarden server or network access."
        ),
    )
    parser.add_argument(
        "--db",
        dest="db_path",
        type=Path,
        default=Path("db.sqlite3"),
        help="Path to the Vaultwarden db.sqlite3 file (default: ./db.sqlite3)",
    )
    parser.add_argument(
        "--export-dir",
        dest="export_dir",
        type=Path,
        default=Path("exports"),
        help="Directory to write exports into (default: ./exports)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    console.print(
        Panel.fit(
            "[bold]Vaultwarden SQLite Toolkit[/bold]\n"
            "Offline vault export & emergency 2FA management\n"
            "[dim]Use only on databases you own or are explicitly authorized to administer.[/dim]",
            border_style="cyan",
        )
    )

    try:
        db.verify_sqlite_file(args.db_path)
    except db.DatabaseError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        return 1

    wal = db.wal_sidecar_status(args.db_path)
    if wal is not None:
        console.print(
            f"[yellow]Notice:[/yellow] found a non-empty WAL sidecar file ({wal.name}). "
            "This usually means the database was copied from a live/running instance "
            "and may have uncommitted transactions not yet visible here."
        )
        if Confirm.ask(
            "Checkpoint the WAL into the main file now for a consistent view?", default=True
        ):
            db.checkpoint_wal(args.db_path)
            console.print("[green]WAL checkpointed.[/green]")

    try:
        return _run_menu(args.db_path, args.export_dir)
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/dim]")
        return 130


# ---------------------------------------------------------------------------
# User selection + authentication
# ---------------------------------------------------------------------------


def _select_user(conn: sqlite3.Connection) -> db.UserRecord | None:
    users = db.list_users(conn)
    if not users:
        console.print("[red]No users found in this database.[/red]")
        return None
    if len(users) == 1:
        console.print(f"[dim]Single user found: {users[0].email}[/dim]")
        return users[0]

    table = Table(title="Users in this database")
    table.add_column("#", justify="right")
    table.add_column("Email")
    table.add_column("Name")
    for idx, user in enumerate(users, start=1):
        table.add_row(str(idx), user.email, user.name or "")
    console.print(table)

    choice = IntPrompt.ask(
        "Select a user by number (filter by email)", choices=[str(i) for i in range(1, len(users) + 1)]
    )
    return users[choice - 1]


def _authenticate(user: db.UserRecord, max_attempts: int = 3) -> tuple[bytes, bytes | None] | None:
    """Prompt for the master password and derive the user's vault key.
    Returns (enc_key, mac_key) on success, None if attempts are exhausted."""
    kdf_type = crypto.KdfType(user.kdf_type)

    for attempt in range(1, max_attempts + 1):
        password = Prompt.ask(f"Master password for {user.email}", password=True)
        try:
            master_key = crypto.derive_master_key(
                password=password,
                email=user.email,
                kdf_type=kdf_type,
                iterations=user.kdf_iterations,
                memory_mib=user.kdf_memory,
                parallelism=user.kdf_parallelism,
            )
            if not crypto.verify_server_password_hash(
                master_key,
                password,
                user.salt,
                user.password_iterations,
                user.password_hash,
            ):
                raise crypto.IncorrectPasswordError("Incorrect master password")

            stretched_enc, stretched_mac = crypto.stretch_master_key(master_key)
            enc_key, mac_key = crypto.decrypt_user_key(user.akey, stretched_enc, stretched_mac)
            console.print("[green]Master password verified - vault key unlocked.[/green]")
            return enc_key, mac_key
        except crypto.CryptoError as exc:
            remaining = max_attempts - attempt
            console.print(f"[red]{exc}[/red]" + (f" ({remaining} attempt(s) left)" if remaining else ""))

    console.print("[red]Too many failed attempts.[/red]")
    return None


# ---------------------------------------------------------------------------
# Main menu
# ---------------------------------------------------------------------------


def _run_menu(db_path: Path, export_dir: Path) -> int:
    conn = db.open_read_connection(db_path)
    try:
        user = _select_user(conn)
        if user is None:
            return 1

        auth = _authenticate(user)
        if auth is None:
            return 1
        enc_key, mac_key = auth

        while True:
            console.print(
                "\n[bold]Main menu[/bold]\n"
                "  [cyan]1[/cyan]. Extract & Export Vault Data\n"
                "  [cyan]2[/cyan]. 2FA Management & Emergency Removal\n"
                "  [cyan]3[/cyan]. Switch user\n"
                "  [cyan]0[/cyan]. Quit"
            )
            choice = Prompt.ask("Choose an option", choices=["0", "1", "2", "3"], default="0")
            if choice == "0":
                return 0
            if choice == "1":
                _module_export(conn, user, enc_key, mac_key, export_dir)
            elif choice == "2":
                _module_twofactor(db_path, conn, user)
            elif choice == "3":
                new_user = _select_user(conn)
                if new_user is None:
                    continue
                auth = _authenticate(new_user)
                if auth is None:
                    continue
                user, (enc_key, mac_key) = new_user, auth
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Module A: Extract & Export
# ---------------------------------------------------------------------------


def _module_export(
    conn: sqlite3.Connection,
    user: db.UserRecord,
    enc_key: bytes,
    mac_key: bytes | None,
    export_dir: Path,
) -> None:
    ciphers = db.list_ciphers_for_user(conn, user.uuid)
    if not ciphers:
        console.print("[yellow]No ciphers found for this user.[/yellow]")
        return

    items = exporters.decrypt_all_ciphers(ciphers, enc_key, mac_key)

    counts: dict = {}
    for item in items:
        counts[item.type_name] = counts.get(item.type_name, 0) + 1
    summary = ", ".join(f"{v} {k}" for k, v in counts.items())
    console.print(f"Decrypted [bold]{len(items)}[/bold] item(s): {summary}")

    console.print(
        "\nExport format:\n"
        "  [cyan]1[/cyan]. Plaintext (.txt)\n"
        "  [cyan]2[/cyan]. Bitwarden-compatible JSON (.json)\n"
        "  [cyan]3[/cyan]. CSV (.csv)\n"
        "  [cyan]4[/cyan]. All of the above"
    )
    fmt = Prompt.ask("Choose a format", choices=["1", "2", "3", "4"], default="4")

    export_dir.mkdir(parents=True, exist_ok=True)
    safe_email = user.email.replace("@", "_at_").replace(".", "_")
    written: list[Path] = []

    if fmt in ("1", "4"):
        written.append(exporters.export_plaintext(items, export_dir / f"{safe_email}.txt"))
    if fmt in ("2", "4"):
        written.append(exporters.export_json(items, export_dir / f"{safe_email}.json"))
    if fmt in ("3", "4"):
        written.append(exporters.export_csv(items, export_dir / f"{safe_email}.csv"))

    for path in written:
        console.print(f"[green]Wrote {path}[/green]")
    console.print(
        "[bold yellow]Reminder:[/bold yellow] these exports are unencrypted plaintext. "
        "Store them securely and delete them when you're done."
    )


# ---------------------------------------------------------------------------
# Module B: 2FA Management & Emergency Removal
# ---------------------------------------------------------------------------


def _module_twofactor(db_path: Path, conn: sqlite3.Connection, user: db.UserRecord) -> None:
    records = db.list_twofactor_for_user(conn, user.uuid)
    if not records:
        console.print(f"[yellow]No 2FA methods are configured for {user.email}.[/yellow]")
        return

    table = Table(title=f"2FA methods for {user.email}")
    table.add_column("#", justify="right")
    table.add_column("Type")
    table.add_column("Enabled")
    for idx, rec in enumerate(records, start=1):
        table.add_row(
            str(idx),
            db.two_factor_type_name(rec.type),
            "[green]yes[/green]" if rec.enabled else "[dim]no[/dim]",
        )
    console.print(table)

    console.print(
        "\n  [cyan]1[/cyan]. Remove a specific 2FA method\n"
        "  [cyan]2[/cyan]. Remove ALL 2FA methods for this user (full emergency reset)\n"
        "  [cyan]0[/cyan]. Back"
    )
    choice = Prompt.ask("Choose an option", choices=["0", "1", "2"], default="0")
    if choice == "0":
        return

    if choice == "1":
        idx = IntPrompt.ask(
            "Which method number should be removed?", choices=[str(i) for i in range(1, len(records) + 1)]
        )
        target = records[idx - 1]
        type_id: int | None = target.type
        description = db.two_factor_type_name(target.type)
    else:
        type_id = None
        description = "ALL 2FA methods"

    console.print(
        f"\n[bold red]You are about to permanently remove {description} for {user.email}.[/bold red]\n"
        "This disables a security control on this account. Only proceed if you are the account "
        "owner or an authorized administrator performing a legitimate recovery."
    )
    confirm_email = Prompt.ask("Type the user's email address to confirm")
    if confirm_email.strip().lower() != user.email.strip().lower():
        console.print("[red]Email did not match - aborting, nothing was changed.[/red]")
        return
    if not Confirm.ask("Final confirmation - proceed with removal?", default=False):
        console.print("[dim]Aborted, nothing was changed.[/dim]")
        return

    backup_path = db.backup_database(db_path)
    console.print(f"[green]Backup created:[/green] {backup_path}")

    write_conn = db.open_write_connection(db_path)
    try:
        removed = db.delete_twofactor(write_conn, user.uuid, type_id)
    finally:
        write_conn.close()

    console.print(f"[green]Removed {removed} 2FA record(s) for {user.email}.[/green]")


if __name__ == "__main__":
    sys.exit(main())
