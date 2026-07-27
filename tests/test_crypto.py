from __future__ import annotations

import pytest

from vaultwarden_toolkit import crypto


def test_pbkdf2_master_key_is_deterministic():
    k1 = crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    k2 = crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    assert k1 == k2
    assert len(k1) == 32


def test_pbkdf2_master_key_differs_with_password():
    k1 = crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    k2 = crypto.derive_master_key("hunter3", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    assert k1 != k2


def test_pbkdf2_master_key_differs_with_email_salt():
    k1 = crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    k2 = crypto.derive_master_key("hunter2", "b@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    assert k1 != k2


def test_pbkdf2_email_is_case_and_whitespace_normalized():
    k1 = crypto.derive_master_key("hunter2", "A@Example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    k2 = crypto.derive_master_key("hunter2", "  a@example.com  ", crypto.KdfType.PBKDF2_SHA256, 5000)
    assert k1 == k2


def test_argon2id_master_key_basic():
    k1 = crypto.derive_master_key(
        "hunter2", "a@example.com", crypto.KdfType.ARGON2ID, iterations=2, memory_mib=16, parallelism=1
    )
    k2 = crypto.derive_master_key(
        "hunter2", "a@example.com", crypto.KdfType.ARGON2ID, iterations=2, memory_mib=16, parallelism=1
    )
    assert k1 == k2
    assert len(k1) == 32


def test_argon2id_requires_memory_and_parallelism():
    with pytest.raises(ValueError):
        crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.ARGON2ID, iterations=2)


def test_stretch_master_key_matches_hkdf_expand_not_full_hkdf():
    """Regression test: stretch_master_key must use HKDF-Expand (RFC 5869
    section 2.3, master key used directly as the PRK), matching Bitwarden's
    own client source (jslib crypto.service.ts: cryptoFunctionService.hkdfExpand).

    Using full HKDF (extract-then-expand) with an empty salt is NOT
    equivalent - HKDF-Extract with an empty salt still runs the master key
    through one more HMAC round before expanding, producing different (and
    incompatible) enc/mac keys. That specific mix-up previously made this
    tool fail to decrypt anything even with the correct master password.
    """
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

    master_key = crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)

    enc_key, mac_key = crypto.stretch_master_key(master_key)

    expected_enc = HKDFExpand(algorithm=_hashes.SHA256(), length=32, info=b"enc").derive(master_key)
    expected_mac = HKDFExpand(algorithm=_hashes.SHA256(), length=32, info=b"mac").derive(master_key)
    assert enc_key == expected_enc
    assert mac_key == expected_mac

    # And explicitly confirm it does NOT match the full-HKDF-with-empty-salt
    # variant, so this test would have caught the regression.
    wrong_enc = HKDF(algorithm=_hashes.SHA256(), length=32, salt=b"", info=b"enc").derive(master_key)
    assert enc_key != wrong_enc


def test_stretch_master_key_produces_distinct_32_byte_keys():
    master_key = crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    enc_key, mac_key = crypto.stretch_master_key(master_key)
    assert len(enc_key) == 32
    assert len(mac_key) == 32
    assert enc_key != mac_key


def test_master_password_hash_is_deterministic_and_differs_by_password():
    master_key = crypto.derive_master_key("hunter2", "a@example.com", crypto.KdfType.PBKDF2_SHA256, 5000)
    h1 = crypto.compute_master_password_hash(master_key, "hunter2")
    h2 = crypto.compute_master_password_hash(master_key, "hunter2")
    h3 = crypto.compute_master_password_hash(master_key, "hunter3")
    assert h1 == h2
    assert h1 != h3
    assert len(h1) == 32


def test_encstring_roundtrip_authenticated():
    enc_key, mac_key = b"0" * 32, b"1" * 32
    plaintext = "correct horse battery staple"
    encstr = crypto.encrypt_enc_string(plaintext.encode("utf-8"), enc_key, mac_key)
    assert encstr.startswith("2.")
    decrypted = crypto.decrypt_enc_string(encstr, enc_key, mac_key)
    assert decrypted == plaintext


def test_encstring_roundtrip_unauthenticated_type_zero():
    enc_key = b"0" * 32
    plaintext = "legacy value"
    encstr = crypto.encrypt_enc_string(plaintext.encode("utf-8"), enc_key, mac_key=None)
    assert encstr.startswith("0.")
    decrypted = crypto.decrypt_enc_string(encstr, enc_key, mac_key=None)
    assert decrypted == plaintext


def test_encstring_tampered_mac_is_rejected():
    enc_key, mac_key = b"0" * 32, b"1" * 32
    encstr = crypto.encrypt_enc_string(b"secret value", enc_key, mac_key)
    es = crypto.EncString.parse(encstr)
    tampered = crypto.EncString(es.enc_type, es.iv, es.ciphertext, bytes(32))  # zeroed-out MAC
    with pytest.raises(crypto.MacVerificationError):
        crypto.decrypt_enc_string(tampered.serialize(), enc_key, mac_key)


def test_encstring_wrong_key_is_rejected():
    enc_key, mac_key = b"0" * 32, b"1" * 32
    wrong_enc_key, wrong_mac_key = b"2" * 32, b"3" * 32
    encstr = crypto.encrypt_enc_string(b"secret value", enc_key, mac_key)
    with pytest.raises(crypto.MacVerificationError):
        crypto.decrypt_enc_string(encstr, wrong_enc_key, wrong_mac_key)


def test_encstring_parse_rejects_malformed_input():
    with pytest.raises(ValueError):
        crypto.EncString.parse("not-a-valid-encstring")


def test_encstring_parse_rejects_unknown_type():
    with pytest.raises(crypto.UnsupportedEncTypeError):
        crypto.EncString.parse("99.AAAA|BBBB|CCCC")


def test_decrypt_enc_string_handles_none_and_empty():
    assert crypto.decrypt_enc_string(None, b"0" * 32, b"1" * 32) is None
    assert crypto.decrypt_enc_string("", b"0" * 32, b"1" * 32) is None


def test_decrypt_user_key_splits_64_bytes_into_enc_and_mac():
    stretched_enc, stretched_mac = b"a" * 32, b"b" * 32
    raw_user_key = b"\x01" * 32 + b"\x02" * 32
    akey = crypto.encrypt_enc_string(raw_user_key, stretched_enc, stretched_mac)
    user_enc, user_mac = crypto.decrypt_user_key(akey, stretched_enc, stretched_mac)
    assert user_enc == b"\x01" * 32
    assert user_mac == b"\x02" * 32


def test_looks_like_enc_string_heuristic():
    assert crypto.looks_like_enc_string("2.aaaa==|bbbb==|cccc==") is True
    assert crypto.looks_like_enc_string("plain text value") is False
    assert crypto.looks_like_enc_string(None) is False
    assert crypto.looks_like_enc_string(True) is False
    assert crypto.looks_like_enc_string("2024-01-01T00:00:00Z") is False
