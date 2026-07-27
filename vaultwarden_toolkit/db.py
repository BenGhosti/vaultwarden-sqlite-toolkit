"""
vaultwarden_toolkit.db
=======================

All direct SQLite access lives here. The rest of the package never touches
``sqlite3`` directly.

Design principles:

* Every read defaults to a read-only connection (``mode=ro`` URI), so simply
  browsing users/ciphers/2FA state can never corrupt or lock the live
  Vaultwarden database.
* Any function that *writes* requires an explicit read-only=False connection,
  obtained only through :func:`open_write_connection`, and callers in
  ``cli.py`` are required to take a timestamped backup first via
  :func:`backup_database`.
* If the database was recently copied out from under a running Vaultwarden
  instance, SQLite may still be in WAL mode with an accompanying ``-wal``/
  ``-shm`` sidecar file. :func:`wal_sidecar_status` and :func:`checkpoint_wal`
  exist so callers can detect and safely fold that state back into the main
  file before treating it as authoritative.
"""

from __future__ import annotations

import shutil
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CipherRecord",
    "DatabaseError",
    "TwoFactorRecord",
    "UserRecord",
    "backup_database",
    "checkpoint_wal",
    "delete_twofactor",
    "get_user_by_uuid",
    "list_ciphers_for_user",
    "list_twofactor_for_user",
    "list_users",
    "open_read_connection",
    "open_write_connection",
    "verify_sqlite_file",
    "wal_sidecar_status",
]


class DatabaseError(Exception):
    """Raised for anything that goes wrong talking to the sqlite file."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UserRecord:
    uuid: str
    email: str
    name: str | None
    akey: str
    private_key: str | None
    password_hash: bytes
    kdf_type: int
    kdf_iterations: int
    kdf_memory: int | None
    kdf_parallelism: int | None


@dataclass(frozen=True)
class CipherRecord:
    uuid: str
    user_uuid: str | None
    organization_uuid: str | None
    type: int
    name: str | None
    notes: str | None
    data: str | None
    fields: str | None
    deleted_at: str | None


@dataclass(frozen=True)
class TwoFactorRecord:
    uuid: str
    user_uuid: str
    type: int
    enabled: bool
    data: str | None


# Bitwarden's TwoFactorProviderType enum. Older/newer Vaultwarden releases have
# occasionally added values; verify against your own instance's source if a
# type shows up as "Unknown".
TWO_FACTOR_TYPE_NAMES = {
    0: "Authenticator (TOTP)",
    1: "Email",
    2: "Duo",
    3: "YubiKey OTP",
    4: "U2F (legacy)",
    5: "Remember Device",
    6: "Organization Duo",
    7: "WebAuthn (FIDO2)",
}


def two_factor_type_name(type_id: int) -> str:
    return TWO_FACTOR_TYPE_NAMES.get(type_id, f"Unknown ({type_id})")


# ---------------------------------------------------------------------------
# File-level helpers
# ---------------------------------------------------------------------------


def verify_sqlite_file(db_path: Path) -> None:
    """Raise DatabaseError if db_path doesn't look like an SQLite database."""
    if not db_path.exists():
        raise DatabaseError(f"Database file not found: {db_path}")
    if not db_path.is_file():
        raise DatabaseError(f"Not a file: {db_path}")
    with db_path.open("rb") as fh:
        header = fh.read(16)
    if header != b"SQLite format 3\x00":
        raise DatabaseError(
            f"{db_path} does not look like an SQLite database "
            "(unexpected file header - is this really a db.sqlite3 file?)"
        )


def wal_sidecar_status(db_path: Path) -> Path | None:
    """Return the path to a non-empty ``-wal`` sidecar file if one exists,
    which indicates there are writes not yet folded into the main db file."""
    wal_path = db_path.with_name(db_path.name + "-wal")
    if wal_path.exists() and wal_path.stat().st_size > 0:
        return wal_path
    return None


def checkpoint_wal(db_path: Path) -> None:
    """Force SQLite to fold the WAL file back into the main database file.
    Requires a normal (non-read-only) connection."""
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.commit()
    finally:
        conn.close()


def backup_database(db_path: Path) -> Path:
    """Copy db.sqlite3 (and any -wal/-shm sidecars) to a timestamped backup
    before any write operation. Returns the path to the primary backup file."""
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    backup_path = db_path.with_name(f"{db_path.name}.bak_{timestamp}")
    shutil.copy2(db_path, backup_path)
    for suffix in ("-wal", "-shm"):
        sidecar = db_path.with_name(db_path.name + suffix)
        if sidecar.exists():
            shutil.copy2(sidecar, backup_path.with_name(backup_path.name + suffix))
    return backup_path


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------


def open_read_connection(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path.as_posix()}?mode=ro"
    try:
        conn = sqlite3.connect(uri, uri=True)
    except sqlite3.OperationalError as exc:
        raise DatabaseError(f"Could not open {db_path} read-only: {exc}") from exc
    conn.row_factory = sqlite3.Row
    return conn


def open_write_connection(db_path: Path) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(str(db_path))
    except sqlite3.OperationalError as exc:
        raise DatabaseError(f"Could not open {db_path} for writing: {exc}") from exc
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


# ---------------------------------------------------------------------------
# Queries
# ---------------------------------------------------------------------------


def list_users(conn: sqlite3.Connection) -> list[UserRecord]:
    try:
        rows = conn.execute(
            """
            SELECT uuid, email, name, akey, private_key, password_hash,
                   client_kdf_type, client_kdf_iter, client_kdf_memory,
                   client_kdf_parallelism
            FROM users
            ORDER BY email COLLATE NOCASE
            """
        ).fetchall()
    except sqlite3.OperationalError as exc:
        raise DatabaseError(
            f"Failed to query 'users' table - is this a valid Vaultwarden database? ({exc})"
        ) from exc

    return [
        UserRecord(
            uuid=row["uuid"],
            email=row["email"],
            name=row["name"],
            akey=row["akey"],
            private_key=row["private_key"],
            password_hash=row["password_hash"],
            kdf_type=row["client_kdf_type"],
            kdf_iterations=row["client_kdf_iter"],
            kdf_memory=row["client_kdf_memory"],
            kdf_parallelism=row["client_kdf_parallelism"],
        )
        for row in rows
    ]


def get_user_by_uuid(conn: sqlite3.Connection, user_uuid: str) -> UserRecord | None:
    for user in list_users(conn):
        if user.uuid == user_uuid:
            return user
    return None


def list_ciphers_for_user(conn: sqlite3.Connection, user_uuid: str) -> list[CipherRecord]:
    try:
        rows = conn.execute(
            """
            SELECT uuid, user_uuid, organization_uuid, type, name, notes, data,
                   fields, deleted_at
            FROM ciphers
            WHERE user_uuid = ?
            ORDER BY name COLLATE NOCASE
            """,
            (user_uuid,),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        raise DatabaseError(
            f"Failed to query 'ciphers' table - is this a valid Vaultwarden database? ({exc})"
        ) from exc

    return [
        CipherRecord(
            uuid=row["uuid"],
            user_uuid=row["user_uuid"],
            organization_uuid=row["organization_uuid"],
            type=row["type"],
            name=row["name"],
            notes=row["notes"],
            data=row["data"],
            fields=row["fields"],
            deleted_at=row["deleted_at"],
        )
        for row in rows
    ]


def list_twofactor_for_user(conn: sqlite3.Connection, user_uuid: str) -> list[TwoFactorRecord]:
    try:
        rows = conn.execute(
            """
            SELECT uuid, user_uuid, type, enabled, data
            FROM twofactor
            WHERE user_uuid = ?
            ORDER BY type
            """,
            (user_uuid,),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        raise DatabaseError(
            f"Failed to query 'twofactor' table - is this a valid Vaultwarden database? ({exc})"
        ) from exc

    return [
        TwoFactorRecord(
            uuid=row["uuid"],
            user_uuid=row["user_uuid"],
            type=row["type"],
            enabled=bool(row["enabled"]),
            data=row["data"],
        )
        for row in rows
    ]


def delete_twofactor(
    conn: sqlite3.Connection, user_uuid: str, type_id: int | None = None
) -> int:
    """Delete 2FA records for a user. If type_id is None, removes ALL 2FA
    methods for that user (complete emergency removal); otherwise removes only
    the matching provider type. Returns the number of rows deleted.

    Caller is responsible for taking a backup first (see backup_database) -
    this function performs the write and commits, nothing more.
    """
    conn.execute("BEGIN;")
    try:
        if type_id is None:
            cur = conn.execute("DELETE FROM twofactor WHERE user_uuid = ?;", (user_uuid,))
        else:
            cur = conn.execute(
                "DELETE FROM twofactor WHERE user_uuid = ? AND type = ?;",
                (user_uuid, type_id),
            )
        conn.commit()
        return cur.rowcount
    except sqlite3.OperationalError as exc:
        conn.rollback()
        raise DatabaseError(f"Failed to delete twofactor rows: {exc}") from exc
