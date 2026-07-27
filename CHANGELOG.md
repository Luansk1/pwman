# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-26

### Added
- **Full-database encryption** with SQLCipher; vaults use the `.pwv` extension and
  carry an `application_id` recognition magic (`PWM1`).
- **Interactive `list` UI** (FTXUI): navigable table with fixed-width password
  masking, live TOTP codes, search/filter, reveal, and clipboard copy.
- **TOTP (2FA)** support: `totp add` / `totp del` / `totp`, with a live,
  self-updating code display.
- **Export** to CSV (RFC 4180) and XML.
- **Import** from CSV, accepting the common `Title, Username, Password, URL,
  Notes, TOTP` column layout (KeePassXC-compatible) and `otpauth://` TOTP URIs.
- **Configurable default vault**: `config` command, `PWMAN_DB` environment
  variable, and `--db` override.
- `--version` / `-v` flag.
- Documentation set under `docs/` and a test-vault generator (`scripts/`).

### Changed
- The entire database is now encrypted, so `list` and every other command
  require the master password.
- TOTP codes are zero-padded to the correct width and use integer modulo.

### Security
- Constant-time master-password verification, broader secret zeroization, and
  `0600`/`0700` permissions on vault files and directories.

### Breaking
- The encrypted `.pwv` vault format is not compatible with the original plaintext
  `1.0.0` database. Re-initialize a new vault (no automatic migration).

## [1.0.0]

### Added
- Initial release: SQLite-backed password manager with Argon2id key derivation,
  XChaCha20-Poly1305 field encryption, and the `init` / `add` / `get` / `list` /
  `del` / `gen` commands.

[2.0.0]: https://github.com/Luansk1/pwman/releases/tag/v2.0.0
[1.0.0]: https://github.com/Luansk1/pwman/releases/tag/v1.0.0
