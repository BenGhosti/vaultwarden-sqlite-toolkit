from __future__ import annotations

import json
import sqlite3

import pytest

from vaultwarden_toolkit import crypto, db, exporters


def test_verify_sqlite_file_accepts_real_db_and_rejects_garbage(tmp_path, fake_vault):
    db.verify_sqlite_file(fake_vault.db_path)  # should not raise

    not_a_db = tmp_path / "not_a_db.sqlite3"
    not_a_db.write_text("hello, this is not sqlite")
    with pytest.raises(db.DatabaseError):
        db.verify_sqlite_file(not_a_db)

    with pytest.raises(db.DatabaseError):
        db.verify_sqlite_file(tmp_path / "does_not_exist.sqlite3")


def test_list_users_returns_expected_record(fake_vault):
    conn = db.open_read_connection(fake_vault.db_path)
    try:
        users = db.list_users(conn)
        assert len(users) == 1
        user = users[0]
        assert user.email == fake_vault.email
        assert user.uuid == fake_vault.user_uuid
        assert user.kdf_type == int(crypto.KdfType.PBKDF2_SHA256)
    finally:
        conn.close()


def test_read_connection_cannot_write(fake_vault):
    conn = db.open_read_connection(fake_vault.db_path)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM twofactor;")
            conn.commit()
    finally:
        conn.close()


def test_full_pipeline_auth_and_decrypt_login_cipher(fake_vault):
    conn = db.open_read_connection(fake_vault.db_path)
    try:
        user = db.get_user_by_uuid(conn, fake_vault.user_uuid)
        assert user is not None

        master_key = crypto.derive_master_key(
            password=fake_vault.master_password,
            email=user.email,
            kdf_type=crypto.KdfType(user.kdf_type),
            iterations=user.kdf_iterations,
        )
        computed_hash = crypto.compute_master_password_hash(master_key, fake_vault.master_password)
        assert computed_hash == user.password_hash

        stretched_enc, stretched_mac = crypto.stretch_master_key(master_key)
        enc_key, mac_key = crypto.decrypt_user_key(user.akey, stretched_enc, stretched_mac)

        ciphers = db.list_ciphers_for_user(conn, user.uuid)
        assert len(ciphers) == 2

        items = exporters.decrypt_all_ciphers(ciphers, enc_key, mac_key)
        by_uuid = {item.cipher_uuid: item for item in items}

        login = by_uuid[fake_vault.login_cipher_uuid]
        assert login.name == "Example Login"
        assert login.username == fake_vault.plain_username
        assert login.password == fake_vault.plain_password
        assert login.totp == fake_vault.plain_totp
        assert login.uris == [fake_vault.plain_uri]
        assert login.custom_fields[fake_vault.plain_field_name] == fake_vault.plain_field_value

        note = by_uuid[fake_vault.note_cipher_uuid]
        assert note.name == fake_vault.plain_note_name
        assert note.notes == fake_vault.plain_note_body
    finally:
        conn.close()


def test_wrong_master_password_is_rejected(fake_vault):
    conn = db.open_read_connection(fake_vault.db_path)
    try:
        user = db.get_user_by_uuid(conn, fake_vault.user_uuid)
        master_key = crypto.derive_master_key(
            password="totally-wrong-password",
            email=user.email,
            kdf_type=crypto.KdfType(user.kdf_type),
            iterations=user.kdf_iterations,
        )
        computed_hash = crypto.compute_master_password_hash(master_key, "totally-wrong-password")
        assert computed_hash != user.password_hash
    finally:
        conn.close()


def test_export_writers_produce_expected_content(tmp_path, fake_vault):
    conn = db.open_read_connection(fake_vault.db_path)
    try:
        user = db.get_user_by_uuid(conn, fake_vault.user_uuid)
        master_key = crypto.derive_master_key(
            fake_vault.master_password, user.email, crypto.KdfType(user.kdf_type), user.kdf_iterations
        )
        stretched_enc, stretched_mac = crypto.stretch_master_key(master_key)
        enc_key, mac_key = crypto.decrypt_user_key(user.akey, stretched_enc, stretched_mac)
        ciphers = db.list_ciphers_for_user(conn, user.uuid)
        items = exporters.decrypt_all_ciphers(ciphers, enc_key, mac_key)
    finally:
        conn.close()

    txt_path = exporters.export_plaintext(items, tmp_path / "out.txt")
    text = txt_path.read_text(encoding="utf-8")
    assert fake_vault.plain_password in text
    assert fake_vault.plain_note_body in text

    json_path = exporters.export_json(items, tmp_path / "out.json")
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["encrypted"] is False
    login_entries = [e for e in payload["items"] if e["type"] == 1]
    assert login_entries[0]["login"]["password"] == fake_vault.plain_password

    csv_path = exporters.export_csv(items, tmp_path / "out.csv")
    csv_text = csv_path.read_text(encoding="utf-8")
    assert fake_vault.plain_username in csv_text


def test_list_twofactor_for_user(fake_vault):
    conn = db.open_read_connection(fake_vault.db_path)
    try:
        records = db.list_twofactor_for_user(conn, fake_vault.user_uuid)
        assert len(records) == 2
        types = {r.type for r in records}
        assert types == {0, 7}
        assert all(r.enabled for r in records)
    finally:
        conn.close()


def test_backup_database_creates_timestamped_copy(fake_vault):
    backup_path = db.backup_database(fake_vault.db_path)
    assert backup_path.exists()
    assert backup_path.name.startswith("db.sqlite3.bak_")
    assert backup_path.read_bytes() == fake_vault.db_path.read_bytes()


def test_delete_twofactor_specific_type(fake_vault):
    write_conn = db.open_write_connection(fake_vault.db_path)
    try:
        removed = db.delete_twofactor(write_conn, fake_vault.user_uuid, type_id=0)
        assert removed == 1
    finally:
        write_conn.close()

    read_conn = db.open_read_connection(fake_vault.db_path)
    try:
        remaining = db.list_twofactor_for_user(read_conn, fake_vault.user_uuid)
        assert len(remaining) == 1
        assert remaining[0].type == 7
    finally:
        read_conn.close()


def test_delete_twofactor_all(fake_vault):
    write_conn = db.open_write_connection(fake_vault.db_path)
    try:
        removed = db.delete_twofactor(write_conn, fake_vault.user_uuid, type_id=None)
        assert removed == 2
    finally:
        write_conn.close()

    read_conn = db.open_read_connection(fake_vault.db_path)
    try:
        remaining = db.list_twofactor_for_user(read_conn, fake_vault.user_uuid)
        assert remaining == []
    finally:
        read_conn.close()


def test_wal_sidecar_status_detects_nontrivial_wal_file(fake_vault):
    assert db.wal_sidecar_status(fake_vault.db_path) is None
    wal_path = fake_vault.db_path.with_name(fake_vault.db_path.name + "-wal")
    wal_path.write_bytes(b"\x00" * 128)
    assert db.wal_sidecar_status(fake_vault.db_path) == wal_path
