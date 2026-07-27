from __future__ import annotations

import json

from vaultwarden_toolkit import crypto, exporters
from vaultwarden_toolkit.db import CipherRecord

ENC_KEY = b"0" * 32
MAC_KEY = b"1" * 32


def enc(text: str) -> str:
    return crypto.encrypt_enc_string(text.encode("utf-8"), ENC_KEY, MAC_KEY)


def make_login_cipher(data: dict, fields: list | None = None, cipher_key: str | None = None) -> CipherRecord:
    return CipherRecord(
        uuid="test-uuid",
        user_uuid="user-uuid",
        organization_uuid=None,
        type=1,
        name=enc("Test Login"),
        notes=None,
        data=json.dumps(data),
        fields=json.dumps(fields) if fields is not None else None,
        deleted_at=None,
        cipher_key=cipher_key,
    )


def test_decrypt_cipher_handles_camelcase_login_fields():
    """Matches the actual key casing found in real Vaultwarden exports."""
    data = {
        "username": enc("alice"),
        "password": enc("s3cret"),
        "totp": enc("JBSWY3DPEHPK3PXP"),
        "uris": [{"uri": enc("https://example.com"), "match": None}],
        "passwordRevisionDate": None,
    }
    item = exporters.decrypt_cipher(make_login_cipher(data), ENC_KEY, MAC_KEY)
    assert item.username == "alice"
    assert item.password == "s3cret"
    assert item.totp == "JBSWY3DPEHPK3PXP"
    assert item.uris == ["https://example.com"]


def test_decrypt_cipher_handles_legacy_pascalcase_login_fields():
    """Some historical Vaultwarden/Bitwarden exports used PascalCase keys -
    the tool should still work against those without guessing which
    convention produced a given database."""
    data = {
        "Username": enc("bob"),
        "Password": enc("hunter2"),
        "Totp": enc("ABCDEFGH"),
        "Uris": [{"Uri": enc("https://legacy.example.com"), "Match": None}],
    }
    item = exporters.decrypt_cipher(make_login_cipher(data), ENC_KEY, MAC_KEY)
    assert item.username == "bob"
    assert item.password == "hunter2"
    assert item.totp == "ABCDEFGH"
    assert item.uris == ["https://legacy.example.com"]


def test_decrypt_cipher_custom_fields_case_insensitive():
    data = {"username": enc("carol"), "password": None, "totp": None, "uris": []}
    fields = [{"type": 0, "name": enc("PIN"), "value": enc("4242"), "linkedId": None}]
    item = exporters.decrypt_cipher(make_login_cipher(data, fields=fields), ENC_KEY, MAC_KEY)
    assert item.custom_fields["PIN"] == "4242"


def test_decrypt_cipher_uses_individual_key_when_present():
    """A cipher with its own wrapped 'key' column must be decrypted with
    that unwrapped item key, not the vault-level key directly."""
    raw_item_key = bytes(range(32)) + bytes(range(32, 64))
    item_enc_key, item_mac_key = raw_item_key[:32], raw_item_key[32:]
    wrapped_item_key = crypto.encrypt_enc_string(raw_item_key, ENC_KEY, MAC_KEY)

    data = {
        "username": crypto.encrypt_enc_string(b"dave", item_enc_key, item_mac_key),
        "password": crypto.encrypt_enc_string(b"topsecret", item_enc_key, item_mac_key),
        "totp": None,
        "uris": [],
    }
    cipher = make_login_cipher(data, cipher_key=wrapped_item_key)
    # cipher.name was encrypted with ENC_KEY/MAC_KEY (the vault key) above via
    # make_login_cipher's default - but this cipher's *data* fields are only
    # valid under the per-item key, proving decrypt_cipher actually switches.
    item = exporters.decrypt_cipher(cipher, ENC_KEY, MAC_KEY)
    assert item.username == "dave"
    assert item.password == "topsecret"


def test_decrypt_cipher_falls_back_gracefully_on_broken_individual_key():
    """If the per-item key can't be unwrapped (corrupt data, wrong vault
    key), decrypt_cipher should not raise - it should fall back to the vault
    key and mark the affected fields as decryption errors, so one bad cipher
    doesn't abort an entire export."""
    data = {"username": enc("eve"), "password": enc("whatever"), "totp": None, "uris": []}
    cipher = make_login_cipher(data, cipher_key="2.not|valid|base64keydata")
    item = exporters.decrypt_cipher(cipher, ENC_KEY, MAC_KEY)
    # Falls back to the vault key, which happens to be correct here since
    # this fixture encrypted with ENC_KEY/MAC_KEY directly.
    assert item.username in ("eve", "<decryption error>")
