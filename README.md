# Vaultwarden SQLite Toolkit

![Tests](https://github.com/yourusername/vaultwarden-sqlite-toolkit/actions/workflows/tests.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Status](https://img.shields.io/badge/status-beta-orange)

An **offline**, read-first CLI toolkit for administering a local Vaultwarden
`db.sqlite3` file directly — no running Vaultwarden server, admin token, or
network connection required.

It implements the standard Bitwarden client-side crypto (PBKDF2-HMAC-SHA256
or Argon2id key derivation, AES-256-CBC + HMAC-SHA256 authenticated
encryption) to unlock a user's vault key from their **master password**, and
provides two focused workflows on top of that:

- **Export a user's vault** to plaintext, Bitwarden-compatible JSON, or CSV.
- **List and remove 2FA methods** for account-recovery / emergency-access
  scenarios (e.g. an admin helping a user who lost their TOTP device or
  security key), with mandatory timestamped backups before any write.

---

## ⚠️ Read this before using it

- **You need the master password.** This tool does not crack, brute-force, or
  bypass master passwords. Vault data stays encrypted and unreadable without
  the correct password for the account in question.
- **Only use this on a database you own, or one you are explicitly
  authorized to administer** (your own self-hosted instance, or as an admin
  performing a recovery a user has asked for). Removing someone's 2FA
  disables a security control on their account — do this with their
  knowledge, not without it.
- **Exports are unencrypted plaintext.** Anything written to `exports/`
  (or wherever you point `--export-dir`) is as sensitive as the vault itself.
  Store it somewhere secure and delete it when you're done — `.gitignore`
  in this repo already excludes these files by default.
- **Always work on a copy** where practical. The tool takes its own
  timestamped backup (`db.sqlite3.bak_<timestamp>`) before any write, but
  operating on a copy of the live file (with a running Vaultwarden instance
  stopped, or at least its `-wal`/`-shm` sidecar files checkpointed) is the
  safest way to avoid corrupting a database another process still has open.
- This project is **not affiliated with Bitwarden Inc. or the Vaultwarden
  project**. It's an independent client built against their published,
  open-source security model.

---

## Features

### Module A — Extract & Export Vault Data
- Decrypts Logins, Secure Notes, Cards, and Identities for a chosen user.
- Handles custom fields and login URIs/TOTP seeds.
- Exports to:
  - **Plaintext** (`.txt`) — simple, human-readable dump.
  - **Bitwarden-compatible JSON** (`.json`) — importable back into any
    Bitwarden/Vaultwarden client via *File → Import data → Bitwarden (json)*.
  - **CSV** (`.csv`) — spreadsheet-friendly, matches Bitwarden's CSV export
    column layout.
- User selection doubles as the "filter by email" step — since vault
  decryption is inherently per-user (each user has their own master
  password), you pick the account to export by email from the users table.

### Module B — 2FA Management & Emergency Removal
- Lists every user and their configured 2FA providers (TOTP, WebAuthn,
  YubiKey OTP, Duo, Email, etc.) read from the `twofactor` table.
- Remove a **single targeted method** (e.g. just a lost YubiKey) or **all**
  2FA for a user in one action.
- Requires typing the target email back as confirmation, plus a final
  yes/no prompt, before anything is written.
- Automatically creates a timestamped backup
  (`db.sqlite3.bak_YYYYMMDD_HHMMSS`, including `-wal`/`-shm` sidecars if
  present) before the delete is executed.

---

## Installation

```bash
git clone https://github.com/yourusername/vaultwarden-sqlite-toolkit.git
cd vaultwarden-sqlite-toolkit
pip install -e .
```

Requires Python 3.9+. Dependencies: `cryptography`, `rich`, `argon2-cffi`.

## Usage

```bash
# Point it at your Vaultwarden database
vaultwarden-toolkit --db /path/to/db.sqlite3 --export-dir ./exports

# Or, without installing the console script:
python -m vaultwarden_toolkit --db /path/to/db.sqlite3
```

You'll be shown the users in the database (or auto-selected if there's only
one), prompted for that user's master password, and then land on a menu:

```
Main menu
  1. Extract & Export Vault Data
  2. 2FA Management & Emergency Removal
  3. Switch user
  0. Quit
```

If a `-wal` sidecar file is detected next to the database (common when a
file has just been copied off a running instance), the tool offers to
checkpoint it into the main file first so you're working against a
consistent, complete view of the data.

---

## Architecture

```
vaultwarden_toolkit/
├── crypto.py      # KDF derivation (PBKDF2 / Argon2id), EncString parse/encrypt/decrypt
├── db.py          # All sqlite3 access: read-only queries, backups, guarded writes
├── exporters.py   # Cipher -> plaintext decryption, plus txt/json/csv writers
└── cli.py         # rich-based interactive menu, argument parsing, entry point
```

**Why the crypto works the way it does:** Bitwarden/Vaultwarden derive a
32-byte *Master Key* from `KDF(masterPassword, salt=email)`, then
HKDF-Expand that into a 32-byte encryption key and a 32-byte MAC key (the
*Stretched Master Key*). That stretched key decrypts `users.akey`, an
authenticated `AES-256-CBC + HMAC-SHA256` blob ("EncString"), which contains
the user's actual 64-byte vault key (32-byte AES key + 32-byte MAC key).
Every cipher field (`name`, `notes`, login `Username`/`Password`/`Totp`,
card/identity fields, custom fields) is just another EncString encrypted
with that same vault key. `crypto.py` implements exactly these primitives;
nothing more, nothing less.

**Why field decryption is schema-generic:** rather than hard-coding the
exact shape of the `data`/`fields` JSON blobs for every cipher type (which
has drifted slightly across Vaultwarden releases), `exporters.py` walks the
parsed JSON and decrypts any string value that *looks like* an EncString
(`type.iv|ct|mac`), leaving everything else (booleans, plain dates, nulls)
untouched. This makes the tool tolerant of minor schema differences instead
of silently dropping fields it doesn't recognize by name.

**Known limitations:**
- Organization-owned ciphers (shared vaults) use RSA-wrapped organization
  keys, which this tool does not decrypt — only personal vault items owned
  directly by the selected user.
- Attachments are not downloaded/decrypted (Vaultwarden stores attachment
  blobs on disk, not in the sqlite file).
- The `TWO_FACTOR_TYPE_NAMES` mapping in `db.py` reflects Bitwarden's
  published `TwoFactorProviderType` enum; if your Vaultwarden version has
  added new provider types, unrecognized ones will show as `Unknown (N)`
  rather than crashing.

---

## Running the tests

```bash
pip install -e ".[dev]"
pytest
```

The test suite builds a small synthetic Vaultwarden-schema database with a
known master password, derives real keys, encrypts real fixture data with
this project's own crypto code, and then exercises the full pipeline —
authenticate → unlock vault key → decrypt ciphers → export → verify
plaintext round-trips correctly. It also covers rejecting a wrong master
password, MAC-tampering detection, backup creation, and both targeted and
full 2FA removal.

---

## Contributing

Issues and pull requests are welcome. Please run `pytest`, `ruff check .`,
and `mypy vaultwarden_toolkit` before submitting.

## License

MIT — see [LICENSE](LICENSE).
