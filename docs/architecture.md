# Architecture & Security

`pwman` protects your data with **two independent layers of encryption**, both
derived from a single master password, and stores everything in a local
SQLCipher-encrypted file.

## Encryption layers

```
                 Master Password
                  /           \
                 v             v
   SQLCipher (PBKDF2)     Argon2id (salt in DB)
        |                      |
        v                      v
  Whole-file key          256-bit field key
        |                      |
        v                      v
  Encrypted .pwv file    XChaCha20-Poly1305 per field
```

1. **Whole-database encryption (SQLCipher).** The entire SQLite file — table
   names, indexes, structure and values — is encrypted at rest. SQLCipher derives
   the file key from the master password with PBKDF2-HMAC-SHA512; its KDF salt
   lives in the first 16 bytes of the file (the only plaintext part).

2. **Per-field encryption (libsodium).** On top of that, each field (username,
   password, URL, notes, TOTP secret) is independently sealed with
   XChaCha20-Poly1305 authenticated encryption using a unique random nonce. The
   field key is derived with **Argon2id** (`crypto_pwhash`, moderate parameters);
   its salt is stored inside the now-encrypted database.

Using the same password for both layers avoids a chicken-and-egg salt problem:
the Argon2id salt can live *inside* the encrypted database because SQLCipher only
needs the raw passphrase (not a stored salt) to open the file.

## The `.pwv` vault format

- Vaults use the custom **`.pwv`** extension; the CLI refuses any other file name
  (except the offline `gen` command).
- On creation, `pwman` writes a **recognition magic** into the SQLite header:
  `PRAGMA application_id = 0x50574D31` (the ASCII bytes `PWM1`). After a
  successful decrypt, this value is checked to positively confirm the file is a
  genuine pwman vault — so a foreign SQLCipher database that happens to share the
  passphrase is rejected rather than misread.
- Schema versioning is tracked in a `meta` table and migrated forward on open.

## Password verification

The master password is **never stored**. At initialization, the fixed token
`"pwman_verify"` is encrypted with the field key and saved. On unlock, the token
is decrypted and compared in **constant time** (`sodium_memcmp`); a mismatch
means the wrong password. (An incorrect password already fails earlier, when
SQLCipher cannot decrypt the file at all.)

## Memory & filesystem hygiene

- Keys, master passwords and decrypted fields are wiped from memory with
  `sodium_memzero` as soon as they are no longer needed.
- On POSIX systems the vault directory is created `0700` and the database file
  (plus its `-wal` / `-shm` / `-journal` sidecars) is `chmod`'d to `0600`.
- The clipboard is cleared when the live TOTP view exits.

## Threat model

**Protects against:** theft of the vault file at rest (offline attacker sees only
ciphertext and cannot even enumerate table structure), casual inspection, and
password-length inference from the `list` UI (fixed-width masking).

**Does *not* protect against:** a compromised host while the vault is unlocked
(keys and plaintext exist in process memory), a keylogger capturing the master
password, or an attacker who can read a file you produced with `pwman export`
(those are plaintext by design — see [Export](export.md)).

## Cryptographic primitives

| Purpose | Primitive |
|---------|-----------|
| Whole-file key derivation | PBKDF2-HMAC-SHA512 (SQLCipher default) |
| Field key derivation | Argon2id (libsodium `crypto_pwhash`) |
| Field encryption | XChaCha20-Poly1305 (AEAD) |
| TOTP | HMAC-SHA1 (RFC 6238) |
| Constant-time compare / zeroization | `sodium_memcmp` / `sodium_memzero` |
