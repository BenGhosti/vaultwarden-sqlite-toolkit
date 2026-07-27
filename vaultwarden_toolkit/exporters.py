"""
vaultwarden_toolkit.exporters
==============================

Turns encrypted :class:`vaultwarden_toolkit.db.CipherRecord` rows into
plaintext :class:`DecryptedItem` objects, and writes those out as plaintext
text, Bitwarden-compatible unencrypted JSON, or CSV.

Rather than hard-coding the exact shape of the ``data`` JSON blob for every
cipher type (which has drifted slightly across Bitwarden/Vaultwarden
releases), the decryption walk here is generic: every string value found
inside ``data`` or ``fields`` that *looks* like an EncString
(``vaultwarden_toolkit.crypto.looks_like_enc_string``) is decrypted in place;
anything else (booleans, dates, nulls, already-plain values) is passed
through untouched. This makes the tool resilient to minor schema/version
differences instead of silently dropping fields it doesn't recognize.
"""

from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import crypto
from .db import CipherRecord

logger = logging.getLogger(__name__)

CIPHER_TYPE_NAMES = {1: "Login", 2: "Secure Note", 3: "Card", 4: "Identity"}


@dataclass
class DecryptedItem:
    cipher_uuid: str
    type_id: int
    type_name: str
    name: str
    notes: str | None
    username: str | None = None
    password: str | None = None
    totp: str | None = None
    uris: list[str] = field(default_factory=list)
    card_fields: dict[str, Any] = field(default_factory=dict)
    identity_fields: dict[str, Any] = field(default_factory=dict)
    custom_fields: dict[str, Any] = field(default_factory=dict)


def _get_ci(data: dict[str, Any], *aliases: str) -> Any:
    """Look up a key in a cipher's ``data``/``fields``/URI JSON object,
    trying each alias in order and falling back to a case-insensitive scan.

    Vaultwarden's ``ciphers.data`` blob has used different key casing across
    versions - current exports use camelCase (``username``, ``password``,
    ``totp``, ``uris`` -> ``uri``), while some historical tooling and the
    original Bitwarden .NET server used PascalCase (``Username``,
    ``Password``, ...). Rather than assuming one, every lookup in this module
    goes through here so it works against either.
    """
    for alias in aliases:
        if alias in data:
            return data[alias]
    lowered = {k.lower(): v for k, v in data.items()}
    for alias in aliases:
        if alias.lower() in lowered:
            return lowered[alias.lower()]
    return None


def _decrypt_value(value: Any, enc_key: bytes, mac_key: bytes | None) -> Any:
    """Decrypt a single JSON value if it looks like an EncString, otherwise
    return it unchanged."""
    if not crypto.looks_like_enc_string(value):
        return value
    try:
        return crypto.decrypt_enc_string(value, enc_key, mac_key)
    except (crypto.CryptoError, ValueError) as exc:
        logger.warning("Failed to decrypt a field: %s", exc)
        return "<decryption error>"


def decrypt_cipher(
    cipher: CipherRecord, vault_enc_key: bytes, vault_mac_key: bytes | None
) -> DecryptedItem:
    """Decrypt a single cipher.

    Most ciphers are encrypted directly with the user's vault key. Some
    (Bitwarden's "cipher key encryption" feature) instead carry their own
    wrapped key in the ``key`` column; when present, that per-item key is
    unwrapped using the vault key and used for this cipher's own fields
    instead. Mixing the two up produces MAC verification failures on exactly
    the ciphers that have an individual key set.
    """
    enc_key, mac_key = vault_enc_key, vault_mac_key
    if cipher.cipher_key:
        try:
            enc_key, mac_key = crypto.decrypt_cipher_key(cipher.cipher_key, vault_enc_key, vault_mac_key)
        except (crypto.CryptoError, ValueError) as exc:
            logger.warning(
                "Cipher %s has an individual key that failed to unwrap (%s); "
                "falling back to the vault key, fields will likely fail to decrypt",
                cipher.uuid,
                exc,
            )

    name = _decrypt_value(cipher.name, enc_key, mac_key) or "(untitled)"
    notes = _decrypt_value(cipher.notes, enc_key, mac_key)

    item = DecryptedItem(
        cipher_uuid=cipher.uuid,
        type_id=cipher.type,
        type_name=CIPHER_TYPE_NAMES.get(cipher.type, f"Unknown ({cipher.type})"),
        name=name,
        notes=notes,
    )

    data: dict[str, Any] = {}
    if cipher.data:
        try:
            data = json.loads(cipher.data)
        except (json.JSONDecodeError, TypeError):
            logger.warning("Cipher %s has malformed 'data' JSON; skipping", cipher.uuid)

    if cipher.type == 1:  # Login
        item.username = _decrypt_value(_get_ci(data, "username", "Username"), enc_key, mac_key)
        item.password = _decrypt_value(_get_ci(data, "password", "Password"), enc_key, mac_key)
        item.totp = _decrypt_value(_get_ci(data, "totp", "Totp"), enc_key, mac_key)
        for uri_entry in _get_ci(data, "uris", "Uris") or []:
            decrypted_uri = _decrypt_value(_get_ci(uri_entry, "uri", "Uri"), enc_key, mac_key)
            if decrypted_uri:
                item.uris.append(decrypted_uri)
    elif cipher.type == 3:  # Card
        card_keys = (
            ("cardholderName", "CardholderName"),
            ("brand", "Brand"),
            ("number", "Number"),
            ("expMonth", "ExpMonth"),
            ("expYear", "ExpYear"),
            ("code", "Code"),
        )
        for canonical, *aliases in card_keys:
            value = _get_ci(data, canonical, *aliases)
            if value is not None:
                item.card_fields[canonical] = _decrypt_value(value, enc_key, mac_key)
    elif cipher.type == 4:  # Identity
        for key, val in data.items():
            item.identity_fields[key] = _decrypt_value(val, enc_key, mac_key)
    # Secure notes (type 2) have no extra structured data beyond name/notes.

    if cipher.fields:
        try:
            custom = json.loads(cipher.fields)
        except (json.JSONDecodeError, TypeError):
            custom = []
        for entry in custom:
            field_name = _decrypt_value(_get_ci(entry, "name", "Name"), enc_key, mac_key) or "(unnamed field)"
            field_value = _decrypt_value(_get_ci(entry, "value", "Value"), enc_key, mac_key)
            item.custom_fields[field_name] = field_value

    return item


def decrypt_all_ciphers(
    ciphers: list[CipherRecord], enc_key: bytes, mac_key: bytes | None
) -> list[DecryptedItem]:
    return [decrypt_cipher(c, enc_key, mac_key) for c in ciphers if c.deleted_at is None]


# ---------------------------------------------------------------------------
# Export writers
# ---------------------------------------------------------------------------


def export_plaintext(items: list[DecryptedItem], out_path: Path) -> Path:
    lines: list[str] = []
    for item in items:
        lines.append(f"=== {item.name} [{item.type_name}] ===")
        if item.username:
            lines.append(f"Username: {item.username}")
        if item.password:
            lines.append(f"Password: {item.password}")
        if item.totp:
            lines.append(f"TOTP seed: {item.totp}")
        for uri in item.uris:
            lines.append(f"URI: {uri}")
        for key, value in item.card_fields.items():
            lines.append(f"{key}: {value}")
        for key, value in item.identity_fields.items():
            lines.append(f"{key}: {value}")
        for key, value in item.custom_fields.items():
            lines.append(f"Field [{key}]: {value}")
        if item.notes:
            lines.append(f"Notes: {item.notes}")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def export_json(items: list[DecryptedItem], out_path: Path) -> Path:
    """Writes a Bitwarden-compatible *unencrypted* export JSON file
    (importable back into any Bitwarden/Vaultwarden client)."""
    export_items = []
    for item in items:
        entry: dict[str, Any] = {
            "id": item.cipher_uuid,
            "organizationId": None,
            "folderId": None,
            "type": item.type_id,
            "name": item.name,
            "notes": item.notes,
            "favorite": False,
            "fields": [
                {"name": k, "value": v, "type": 0}
                for k, v in item.custom_fields.items()
            ],
        }
        if item.type_id == 1:
            entry["login"] = {
                "username": item.username,
                "password": item.password,
                "totp": item.totp,
                "uris": [{"match": None, "uri": u} for u in item.uris],
            }
        elif item.type_id == 3:
            entry["card"] = item.card_fields
        elif item.type_id == 4:
            entry["identity"] = item.identity_fields
        export_items.append(entry)

    payload = {"encrypted": False, "folders": [], "items": export_items}
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


CSV_FIELDNAMES = [
    "type",
    "name",
    "notes",
    "login_username",
    "login_password",
    "login_totp",
    "login_uri",
    "fields",
]


def export_csv(items: list[DecryptedItem], out_path: Path) -> Path:
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        for item in items:
            extra = {**item.card_fields, **item.identity_fields, **item.custom_fields}
            writer.writerow(
                {
                    "type": item.type_name,
                    "name": item.name,
                    "notes": item.notes or "",
                    "login_username": item.username or "",
                    "login_password": item.password or "",
                    "login_totp": item.totp or "",
                    "login_uri": item.uris[0] if item.uris else "",
                    "fields": json.dumps(extra, ensure_ascii=False) if extra else "",
                }
            )
    return out_path
