"""
Builds a small, self-contained fake Vaultwarden database for the test suite.

Rather than relying on a real, potentially-outdated db.sqlite3 fixture file
(or hard-coded crypto test vectors we can't independently verify), this
fixture derives real keys and produces real, correctly-encrypted EncStrings
for a known master password using the toolkit's own crypto module. This lets
the test-suite exercise the *entire* pipeline end-to-end: derive -> unwrap
akey -> decrypt cipher fields -> export, and confirm it round-trips back to
the original plaintext.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import pytest

from vaultwarden_toolkit import crypto

# Kept intentionally low so the test suite runs in well under a second;
# production Vaultwarden instances default to 600,000 PBKDF2 iterations.
TEST_CLIENT_KDF_ITERATIONS = 5_000
TEST_PASSWORD_ITERATIONS = 5_000

MASTER_PASSWORD = "Correct-Horse-Battery-Staple-42!"
EMAIL = "test.user@example.com"


@dataclass
class FakeVault:
    db_path: Path
    email: str
    master_password: str
    user_uuid: str
    login_cipher_uuid: str
    note_cipher_uuid: str
    plain_username: str
    plain_password: str
    plain_note_name: str
    plain_note_body: str
    plain_totp: str
    plain_uri: str
    plain_field_name: str
    plain_field_value: str


SCHEMA_SQL = """
CREATE TABLE users (
    uuid TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT,
    password_hash BLOB NOT NULL,
    salt BLOB NOT NULL,
    password_iterations INTEGER NOT NULL,
    akey TEXT NOT NULL,
    private_key TEXT,
    client_kdf_type INTEGER NOT NULL,
    client_kdf_iter INTEGER NOT NULL,
    client_kdf_memory INTEGER,
    client_kdf_parallelism INTEGER
);

CREATE TABLE ciphers (
    uuid TEXT PRIMARY KEY,
    user_uuid TEXT,
    organization_uuid TEXT,
    atype INTEGER NOT NULL,
    name TEXT,
    notes TEXT,
    data TEXT,
    fields TEXT,
    deleted_at TEXT
);

CREATE TABLE twofactor (
    uuid TEXT PRIMARY KEY,
    user_uuid TEXT NOT NULL,
    atype INTEGER NOT NULL,
    enabled INTEGER NOT NULL,
    data TEXT
);
"""


@pytest.fixture()
def fake_vault(tmp_path: Path) -> FakeVault:
    db_path = tmp_path / "db.sqlite3"

    # --- Derive real keys for our test user, exactly as a Bitwarden client would ---
    master_key = crypto.derive_master_key(
        password=MASTER_PASSWORD,
        email=EMAIL,
        kdf_type=crypto.KdfType.PBKDF2_SHA256,
        iterations=TEST_CLIENT_KDF_ITERATIONS,
    )
    stretched_enc, stretched_mac = crypto.stretch_master_key(master_key)

    # Vaultwarden two-layer password hash: client-side PBKDF2 + base64,
    # then server-side PBKDF2 with random 64-byte salt.
    import base64 as b64_mod
    salt = os.urandom(64)
    client_hash_raw = crypto.compute_master_password_hash(master_key, MASTER_PASSWORD)
    client_hash_b64 = b64_mod.b64encode(client_hash_raw).decode("ascii")
    password_hash = crypto._pbkdf2_sha256(client_hash_b64.encode("utf-8"), salt, TEST_PASSWORD_ITERATIONS)

    # A random 64-byte "vault key" (32 enc + 32 mac), as Vaultwarden generates at registration.
    raw_user_key = os.urandom(64)
    user_enc_key, user_mac_key = raw_user_key[:32], raw_user_key[32:]

    akey = crypto.encrypt_enc_string(raw_user_key, stretched_enc, stretched_mac)

    user_uuid = "11111111-1111-1111-1111-111111111111"

    # --- Build one encrypted Login cipher and one encrypted Secure Note cipher ---
    def enc(text: str) -> str:
        return crypto.encrypt_enc_string(text.encode("utf-8"), user_enc_key, user_mac_key)

    plain_username = "alice"
    plain_password = "hunter2-super-secret"
    plain_totp = "JBSWY3DPEHPK3PXP"
    plain_uri = "https://example.com/login"
    plain_field_name = "Recovery Code"
    plain_field_value = "RC-9981-XYZ"

    login_data = {
        "Username": enc(plain_username),
        "Password": enc(plain_password),
        "Totp": enc(plain_totp),
        "Uris": [{"Uri": enc(plain_uri), "Match": None}],
        "PasswordRevisionDate": None,
    }
    login_fields = [
        {"Type": 0, "Name": enc(plain_field_name), "Value": enc(plain_field_value), "LinkedId": None}
    ]

    login_cipher_uuid = "22222222-2222-2222-2222-222222222222"
    note_cipher_uuid = "33333333-3333-3333-3333-333333333333"
    plain_note_name = "Wifi Password"
    plain_note_body = "Guest network: SuperSecretWifi123"

    conn = sqlite3.connect(str(db_path))
    conn.executescript(SCHEMA_SQL)
    conn.execute(
        """
        INSERT INTO users (uuid, email, name, password_hash, salt, password_iterations,
                            akey, private_key, client_kdf_type, client_kdf_iter,
                            client_kdf_memory, client_kdf_parallelism)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, NULL, NULL)
        """,
        (user_uuid, EMAIL, "Test User", password_hash, salt, TEST_PASSWORD_ITERATIONS,
         akey, int(crypto.KdfType.PBKDF2_SHA256), TEST_CLIENT_KDF_ITERATIONS),
    )
    conn.execute(
        """
        INSERT INTO ciphers (uuid, user_uuid, organization_uuid, atype, name, notes, data, fields, deleted_at)
        VALUES (?, ?, NULL, 1, ?, NULL, ?, ?, NULL)
        """,
        (login_cipher_uuid, user_uuid, enc("Example Login"), json.dumps(login_data), json.dumps(login_fields)),
    )
    conn.execute(
        """
        INSERT INTO ciphers (uuid, user_uuid, organization_uuid, atype, name, notes, data, fields, deleted_at)
        VALUES (?, ?, NULL, 2, ?, ?, '{}', NULL, NULL)
        """,
        (note_cipher_uuid, user_uuid, enc(plain_note_name), enc(plain_note_body)),
    )
    conn.execute(
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data) VALUES (?, ?, 0, 1, '{}')",
        ("44444444-4444-4444-4444-444444444444", user_uuid),
    )
    conn.execute(
        "INSERT INTO twofactor (uuid, user_uuid, atype, enabled, data) VALUES (?, ?, 7, 1, '{}')",
        ("55555555-5555-5555-5555-555555555555", user_uuid),
    )
    conn.commit()
    conn.close()

    return FakeVault(
        db_path=db_path,
        email=EMAIL,
        master_password=MASTER_PASSWORD,
        user_uuid=user_uuid,
        login_cipher_uuid=login_cipher_uuid,
        note_cipher_uuid=note_cipher_uuid,
        plain_username=plain_username,
        plain_password=plain_password,
        plain_note_name=plain_note_name,
        plain_note_body=plain_note_body,
        plain_totp=plain_totp,
        plain_uri=plain_uri,
        plain_field_name=plain_field_name,
        plain_field_value=plain_field_value,
    )
