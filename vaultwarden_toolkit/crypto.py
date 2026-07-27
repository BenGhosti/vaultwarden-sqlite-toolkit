"""
vaultwarden_toolkit.crypto
==========================

Implements the client-side cryptography used by Bitwarden/Vaultwarden to turn a
user's *master password* into the symmetric key that protects their vault.

This module intentionally re-implements only the well-documented, published
Bitwarden security model (see https://bitwarden.com/help/bitwarden-security-white-paper/)
against data that already lives in a database the operator controls. It never
attempts to brute-force, guess, or otherwise bypass a master password.

High-level flow
----------------
1. ``derive_master_key``      : master password + email  -> Master Key (32 bytes)
2. ``stretch_master_key``     : Master Key                -> (stretched enc key, stretched mac key)
3. ``compute_master_password_hash`` : Master Key + password -> hash comparable to users.password_hash
4. ``decrypt_user_key``       : users.akey (EncString) + stretched keys -> the User (Symmetric) Key
5. ``decrypt_enc_string``     : any other EncString (cipher name, username, password, ...) + User Key -> plaintext

All EncStrings follow the Bitwarden wire format::

    "<enc_type>.<iv_b64>|<ciphertext_b64>|<mac_b64>"

for symmetric AES-256-CBC (+ optional HMAC-SHA256) values, which is what every
field inside the ``ciphers`` table uses.
"""

from __future__ import annotations

import base64
import hashlib
import hmac as hmac_mod
from dataclasses import dataclass
from enum import IntEnum

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

__all__ = [
    "CryptoError",
    "EncString",
    "EncStringType",
    "IncorrectPasswordError",
    "KdfType",
    "MacVerificationError",
    "UnsupportedEncTypeError",
    "compute_master_password_hash",
    "decrypt_cipher_key",
    "decrypt_enc_string",
    "decrypt_enc_string_bytes",
    "decrypt_user_key",
    "derive_master_key",
    "encrypt_enc_string",
    "looks_like_enc_string",
    "stretch_master_key",
    "unwrap_symmetric_key",
    "verify_server_password_hash",
]


class KdfType(IntEnum):
    """Matches Bitwarden's ``KdfType`` enum stored in ``users.client_kdf_type``."""

    PBKDF2_SHA256 = 0
    ARGON2ID = 1


class EncStringType(IntEnum):
    """Matches Bitwarden's ``EncryptionType`` enum (the prefix before the first '.')."""

    AES_CBC_256_B64 = 0  # legacy, no MAC
    AES_CBC_128_HMAC_SHA256_B64 = 1  # not used by modern clients
    AES_CBC_256_HMAC_SHA256_B64 = 2  # standard for all cipher fields + akey
    RSA_2048_OAEP_SHA256_B64 = 3
    RSA_2048_OAEP_SHA1_B64 = 4


class CryptoError(Exception):
    """Base class for all recoverable crypto errors raised by this module."""


class MacVerificationError(CryptoError):
    """Raised when an authenticated EncString's HMAC does not match."""


class UnsupportedEncTypeError(CryptoError):
    """Raised when an EncString uses an encryption type this tool cannot handle."""


class IncorrectPasswordError(CryptoError):
    """Raised when the supplied master password does not match users.password_hash."""


# ---------------------------------------------------------------------------
# EncString parsing
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EncString:
    """A parsed Bitwarden EncString: ``type.iv|ciphertext|mac``."""

    enc_type: EncStringType
    iv: bytes | None
    ciphertext: bytes
    mac: bytes | None

    @classmethod
    def parse(cls, value: str) -> EncString:
        if not value or "." not in value:
            raise ValueError(f"Malformed EncString (no type prefix): {value!r}")
        type_part, _, rest = value.partition(".")
        try:
            enc_type = EncStringType(int(type_part))
        except ValueError as exc:
            raise UnsupportedEncTypeError(
                f"Unknown EncString type prefix {type_part!r} in {value!r}"
            ) from exc

        parts = rest.split("|")
        if enc_type in (EncStringType.AES_CBC_256_B64, EncStringType.AES_CBC_256_HMAC_SHA256_B64):
            if len(parts) not in (2, 3):
                raise ValueError(f"Malformed AES-CBC EncString: {value!r}")
            iv = base64.b64decode(parts[0])
            ciphertext = base64.b64decode(parts[1])
            mac = base64.b64decode(parts[2]) if len(parts) == 3 else None
            return cls(enc_type, iv, ciphertext, mac)

        # RSA-wrapped values (organization sharing, private_key) - single b64 blob.
        ciphertext = base64.b64decode(parts[0])
        return cls(enc_type, None, ciphertext, None)

    def serialize(self) -> str:
        if self.iv is None:
            body = base64.b64encode(self.ciphertext).decode("ascii")
            return f"{int(self.enc_type)}.{body}"
        body = f"{_b64(self.iv)}|{_b64(self.ciphertext)}"
        if self.mac is not None:
            body += f"|{_b64(self.mac)}"
        return f"{int(self.enc_type)}.{body}"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def looks_like_enc_string(value: object) -> bool:
    """Best-effort heuristic used by exporters to decide whether a JSON value
    inside a cipher's ``data``/``fields`` blob is an EncString worth decrypting,
    as opposed to a plain (unencrypted) value such as a boolean or ISO date."""
    if not isinstance(value, str) or "." not in value:
        return False
    prefix, _, rest = value.partition(".")
    if not prefix.isdigit():
        return False
    return "|" in rest or prefix in ("3", "4")


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def derive_master_key(
    password: str,
    email: str,
    kdf_type: KdfType,
    iterations: int,
    memory_mib: int | None = None,
    parallelism: int | None = None,
) -> bytes:
    """Derive the 32-byte Master Key from a master password.

    The salt is always the user's lower-cased, trimmed email address, per the
    Bitwarden spec - this is true for both supported KDFs.
    """
    normalized_email = email.strip().lower()
    if kdf_type == KdfType.PBKDF2_SHA256:
        if iterations <= 0:
            raise ValueError("PBKDF2 iteration count must be positive")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=normalized_email.encode("utf-8"),
            iterations=iterations,
        )
        return kdf.derive(password.encode("utf-8"))

    if kdf_type == KdfType.ARGON2ID:
        if memory_mib is None or parallelism is None:
            raise ValueError("Argon2id requires memory_mib and parallelism")
        salt = hashlib.sha256(normalized_email.encode("utf-8")).digest()
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=iterations,
            memory_cost=memory_mib * 1024,  # Bitwarden stores MiB; argon2-cffi wants KiB
            parallelism=parallelism,
            hash_len=32,
            type=Argon2Type.ID,
            version=19,
        )

    raise ValueError(f"Unsupported KDF type: {kdf_type!r}")


def stretch_master_key(master_key: bytes) -> tuple[bytes, bytes]:
    """HKDF-Expand (RFC 5869 section 2.3, SHA-256) the Master Key into a
    32-byte encryption key and a 32-byte MAC key.

    This is the *expand-only* half of HKDF - the Master Key is used directly
    as the PRK, with no extract phase. Confirmed against Bitwarden's own
    client source (``jslib``'s ``crypto.service.ts``)::

        const encKey = await this.cryptoFunctionService.hkdfExpand(key.key, 'enc', 32, 'sha256');
        const macKey = await this.cryptoFunctionService.hkdfExpand(key.key, 'mac', 32, 'sha256');

    Using full HKDF (extract + expand) with an empty salt is a common
    mix-up, but it is NOT equivalent: HKDF-Extract with an empty salt still
    runs the input through one more HMAC round (``PRK = HMAC(salt="", IKM)``),
    which yields a different key than using IKM directly as the PRK. That
    mistake silently breaks every decryption downstream of it (wrong enc/mac
    keys -> MAC verification failures on ``akey`` and every cipher field)
    even when the master password itself was verified correctly, since
    password verification uses a separate, independent code path (see
    :func:`verify_server_password_hash`). This is why "correct password,
    still can't decrypt anything" is such a deceptive failure mode here.
    """
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master_key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master_key)
    return enc_key, mac_key


def compute_master_password_hash(master_key: bytes, password: str) -> bytes:
    """Compute the client-side master password hash sent between client and server.

    Raw PBKDF2-HMAC-SHA256 output (before base64 encoding). This is NOT what
    is stored in ``users.password_hash`` — that is a *second* server-side
    PBKDF2 applied on top (see :func:`verify_server_password_hash`).
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=password.encode("utf-8"),
        iterations=1,
    )
    return kdf.derive(master_key)


def verify_server_password_hash(
    master_key: bytes, password: str, salt: bytes, password_iterations: int, expected: bytes
) -> bool:
    """Replicate Vaultwarden's two-layer password hash verification.

    * Layer 1 (client-side)::
        client_hash_raw = PBKDF2(master_key, password, 1)  # 32 bytes
        client_hash_b64 = base64(client_hash_raw)           # 44-char ASCII string

    * Layer 2 (server-side, what's stored in ``users.password_hash``)::
        stored_hash = PBKDF2(client_hash_b64_utf8, salt, password_iterations)
    """
    import base64 as b64_mod

    client_hash_raw = compute_master_password_hash(master_key, password)
    client_hash_b64 = b64_mod.b64encode(client_hash_raw).decode("ascii")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=password_iterations,
    )
    computed = kdf.derive(client_hash_b64.encode("utf-8"))
    return hmac_mod.compare_digest(computed, expected)


# ---------------------------------------------------------------------------
# Symmetric encrypt / decrypt primitives
# ---------------------------------------------------------------------------


def _pbkdf2_sha256(password: bytes, salt: bytes, iterations: int, length: int = 32) -> bytes:
    """Low-level PBKDF2-HMAC-SHA256 primitive. Exposed for testing."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=iterations)
    return kdf.derive(password)


def _aes_cbc_decrypt(ciphertext: bytes, iv: bytes, enc_key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _aes_cbc_encrypt(plaintext: bytes, iv: bytes, enc_key: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _decrypt_raw(es: EncString, enc_key: bytes, mac_key: bytes | None) -> bytes:
    if es.enc_type not in (EncStringType.AES_CBC_256_B64, EncStringType.AES_CBC_256_HMAC_SHA256_B64):
        raise UnsupportedEncTypeError(
            f"EncString type {es.enc_type!r} is not a supported symmetric AES-CBC type "
            "(RSA-wrapped organization keys are out of scope for this tool)"
        )
    if es.iv is None:
        raise CryptoError("Symmetric EncString is missing its IV")
    if es.enc_type == EncStringType.AES_CBC_256_HMAC_SHA256_B64:
        if mac_key is None or es.mac is None:
            raise MacVerificationError("Authenticated EncString is missing its MAC or MAC key")
        computed = hmac_mod.new(mac_key, es.iv + es.ciphertext, hashlib.sha256).digest()
        if not hmac_mod.compare_digest(computed, es.mac):
            raise MacVerificationError(
                "MAC verification failed - the derived key does not match this data "
                "(likely an incorrect master password or KDF parameters)"
            )
    return _aes_cbc_decrypt(es.ciphertext, es.iv, enc_key)


def decrypt_enc_string_bytes(
    value: str | None, enc_key: bytes, mac_key: bytes | None = None
) -> bytes | None:
    """Decrypt an EncString and return the raw plaintext bytes (no UTF-8 decode).
    Used for the user's symmetric key, which is not itself valid UTF-8."""
    if value is None or value == "":
        return None
    es = EncString.parse(value)
    return _decrypt_raw(es, enc_key, mac_key)


def decrypt_enc_string(
    value: str | None, enc_key: bytes, mac_key: bytes | None = None
) -> str | None:
    """Decrypt an EncString and return it as a UTF-8 string. This is what
    should be used for every human-readable cipher field."""
    raw = decrypt_enc_string_bytes(value, enc_key, mac_key)
    if raw is None:
        return None
    return raw.decode("utf-8")


def encrypt_enc_string(plaintext_bytes: bytes, enc_key: bytes, mac_key: bytes | None) -> str:
    """Build a valid Bitwarden EncString. Used by the test-suite to generate
    realistic fixtures, and available as a general utility."""
    import os

    iv = os.urandom(16)
    ciphertext = _aes_cbc_encrypt(plaintext_bytes, iv, enc_key)
    if mac_key is not None:
        mac = hmac_mod.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
        es = EncString(EncStringType.AES_CBC_256_HMAC_SHA256_B64, iv, ciphertext, mac)
    else:
        es = EncString(EncStringType.AES_CBC_256_B64, iv, ciphertext, None)
    return es.serialize()


def unwrap_symmetric_key(
    encrypted_value: str, wrapping_enc_key: bytes, wrapping_mac_key: bytes | None
) -> tuple[bytes, bytes | None]:
    """Decrypt an EncString that itself wraps another symmetric key (64 raw
    bytes: 32-byte AES key + 32-byte MAC key), and split it into its two
    halves. This same shape is used both for ``users.akey`` (wrapped by the
    stretched Master Key) and for a cipher's individual ``key`` column
    (wrapped by the user's own vault key) - see :func:`decrypt_user_key` and
    :func:`decrypt_cipher_key`.
    """
    raw = decrypt_enc_string_bytes(encrypted_value, wrapping_enc_key, wrapping_mac_key)
    if raw is None:
        raise CryptoError("Wrapped key value is empty - nothing to unwrap")
    if len(raw) == 64:
        return raw[:32], raw[32:]
    if len(raw) == 32:
        # Legacy/unauthenticated keys occasionally only carry an encryption
        # key with no separate MAC key.
        return raw, None
    raise CryptoError(f"Unexpected unwrapped key length: {len(raw)} bytes (expected 32 or 64)")


def decrypt_user_key(
    encrypted_akey: str, stretched_enc_key: bytes, stretched_mac_key: bytes
) -> tuple[bytes, bytes | None]:
    """Decrypt ``users.akey`` using the stretched Master Key to recover the
    user's actual Symmetric (vault) Key, split into its own enc/mac halves.

    Vaultwarden/Bitwarden generate a 512-bit (64 byte) symmetric key per user:
    the first 32 bytes are the AES-256 key used for every cipher field, and the
    last 32 bytes are the HMAC-SHA256 key used to authenticate them.
    """
    try:
        return unwrap_symmetric_key(encrypted_akey, stretched_enc_key, stretched_mac_key)
    except CryptoError as exc:
        raise CryptoError(f"Could not unwrap users.akey: {exc}") from exc


def decrypt_cipher_key(
    encrypted_key: str, vault_enc_key: bytes, vault_mac_key: bytes | None
) -> tuple[bytes, bytes | None]:
    """Decrypt a cipher's individual ``key`` column (Bitwarden's per-item
    "cipher key encryption" feature) using the already-unwrapped vault key,
    yielding the item-specific enc/mac keys that its own fields are actually
    encrypted with. Only some ciphers have this set - see
    :func:`vaultwarden_toolkit.exporters.decrypt_cipher` for the fallback to
    the vault key when it's absent.
    """
    try:
        return unwrap_symmetric_key(encrypted_key, vault_enc_key, vault_mac_key)
    except CryptoError as exc:
        raise CryptoError(f"Could not unwrap cipher-specific key: {exc}") from exc
