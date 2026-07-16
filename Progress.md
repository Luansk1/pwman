# pwman — Progress

_Last updated: 2026-07-17_

A secure command-line password manager written in C++17. The whole database is now
encrypted at rest with **SQLCipher**, with XChaCha20-Poly1305 (libsodium) field encryption
layered on top, all protected by a single Argon2id-derived master password. Includes
RFC 6238 TOTP (2FA) support with a live, self-updating code display.

## Latest Change — SQLCipher whole-database encryption (2026-07-17)

- **SQLCipher** replaces plain SQLite (`pkg_check_modules(... sqlcipher)`); it is a drop-in
  `<sqlite3.h>` provider, so only the build's link target changed. The entire file — table
  names, indexes, structure — is now opaque at rest, not just the field values.
- **Two layers, one password**: SQLCipher's PBKDF2 whole-file key (KDF salt in the file's
  16-byte plaintext header) plus the existing Argon2id per-field key (salt stored inside the
  now-encrypted DB). This side-steps the chicken-and-egg of needing a salt before opening.
- **Custom vault extension `.pwv`** (`kVaultExtension`): the CLI (`main.cpp`) rejects any DB
  path without it (except offline `gen`). `default_db_path()` → `~/.pwman/pwman.pwv`.
- **Recognition magic**: `PRAGMA application_id = 0x50574D31` ("PWM1", `kApplicationId`) is
  written by `init()` and verified after decryption, so a decrypted file is positively
  identified as a pwman vault (a foreign SQLCipher DB with the same passphrase is rejected).
- **Flow change**: `Database` constructor now takes the master password
  (`Database(path, password, create=false)`), runs `PRAGMA key`, and verifies the passphrase
  + magic. The old `unlock()` (which prompted) was replaced by `open_vault()` (prompt + key)
  and `derive_field_key()` (Argon2id + token check). **`list` now requires the password**,
  since names are no longer readable without decrypting the file.
- Verified end-to-end: init/add/get/list/totp work; the file has no `SQLite format 3` header;
  plain `sqlite3` reports "file is not a database"; wrong password and foreign-DB are both
  rejected. All 88 unit tests pass (`test_database.cpp` updated for the new constructor).
- **Breaking**: old plaintext `~/.pwman/pwman.db` vaults cannot be read; users must re-init
  (or export/re-import) into a new `.pwv` vault. No automatic migration is provided.

## Current State

- **Build**: CMake (>= 3.16), C++17. Static `pwman_lib` shared between the `pwman`
  executable and `pwman_tests` (GoogleTest v1.14.0, fetched via `FetchContent`).
- **Dependencies**: libsodium, SQLite3, pkg-config.
- **Platforms**: Linux, macOS, Windows (guarded with `_WIN32` / `__APPLE__` blocks).

### Modules (`src/` + `includes/`)

| Module | Status | Notes |
|--------|--------|-------|
| `crypto` | Stable | Argon2id key derivation, XChaCha20-Poly1305 encrypt/decrypt, `secure_zero`. |
| `database` | Active | SQLite CRUD, WAL mode, TOTP storage. Hardened this round (see below). |
| `terminal` | Active | Hidden password input, table printing, TOTP box rendering. |
| `commands` | Active | `init`/`add`/`get`/`list`/`del`/`gen` + `totp`/`totp add`. Live TOTP display added. |
| `base32` | Stable | RFC 4648 encode/decode/validate. Debug output removed. |
| `totp` | Stable | RFC 6238 TOTP generation, remaining-seconds helper. |
| `hmac` | Stable | From-scratch SHA-1 / HMAC. UB in bit-rotation fixed. |
| `migrations` | Empty | `src/migrations.cpp` is a placeholder (0 bytes). |

### Commands

`init`, `add`, `get <name>`, `list`, `del <name>`, `gen [length]`,
`totp <name>`, `totp add <name>`, plus `--db <path>` override.

## Latest Changes (uncommitted working tree)

These changes span crypto hygiene, TOTP UX, and cross-platform robustness.

### TOTP: live self-updating display (`commands.cpp`)
- New `live_totp_display()` renders the TOTP box and refreshes it in place every ~200ms,
  regenerating the code as each time-step rolls over.
- Codes are **auto-copied to the clipboard** (`pbcopy` / `clip` / `wl-copy`→`xclip`→`xsel`);
  the clipboard is **cleared on exit** so codes don't linger.
- Terminal put into raw, no-echo mode via RAII `RawModeGuard`; `SIGINT` handled via
  `SigintGuard`; press `q`/`Esc`/Ctrl-C to quit. Windows path uses `_kbhit`/`_getch`/`Sleep`.
- Both `cmd_totp` and `cmd_totp_add` now hand off to the live display instead of printing
  a single static code.
- `otpauth://` URIs: previously fell through with an empty secret — now explicitly rejected
  with a clear error (raw Base32 still supported). Parser remains TODO.

### Security hardening
- **Master-password verification** (`unlock`) now compares the decrypted token in constant
  time via `sodium_memcmp`, and zeroes the plaintext.
- **Broader secret zeroing** in `cmd_add`/`cmd_get`: username, URL, notes and table cells
  are now `secure_zero`'d, not just the password.
- **DB file permissions** (`database.cpp`): DB directory set to `0700`; the DB file and its
  `-wal`/`-shm`/`-journal` sidecars set to `0600` (POSIX only).
- **TOTP input validation** in `Database::set_totp`: rejects bad algorithm, digits (6–8),
  period (1–600), and empty secrets.
- **SHA-1 rotate_left** (`hmac.cpp`): fixed undefined behaviour on shift counts of 0/32.
- **`totp_generate`**: validates digits/period and **re-enabled the sign-bit mask**
  (`code &= 0x7FFFFFFF`) that was previously commented out — this was a correctness bug.

### Password strength (from prior commit, now surfaced in UX)
- `cmd_init` warns when the master password is `WEAK`.
- `cmd_add` and `cmd_gen` print the strength label of generated passwords.

### Cleanup / robustness
- `read_password` (`terminal.cpp`) refactored to RAII `EchoGuard` (Win + POSIX), restoring
  terminal state even on exceptions.
- Removed debug/leftover code: `std::cout` tracing in `base32_validate`, stray
  `base32_validate("")` call in `main.cpp`.
- `base32_validate` now rejects empty input.
- Fixed test include path in `CMakeLists.txt` (`include` → `includes`).

## Tests

GoogleTest suites: `test_crypto`, `test_database`, `test_terminal`, `test_base32`,
`test_hmac`. Run with:

```bash
cd build && cmake --build . && ctest --output-on-failure
```

Coverage: encryption round-trips, key derivation, tamper detection, DB CRUD, table
formatting, Base32, and HMAC/SHA-1.

## Known Gaps / TODO

- **`otpauth://` URI parsing** — stubbed out; only raw Base32 secrets accepted.
- **`migrations.cpp`** — empty placeholder; no schema migration framework yet.
- **README** — "Features coming soon" still lists TOTP/entropy (now implemented) and the
  Project Structure section references `include/` (actual dir is `includes/`).
- Working-tree changes above are **not yet committed**.

## Recent Commit History

```
3563da1 fix: failing unit tests
72a68e5 feat: sha1 based TOTP added
387ec62 add: entropy calculation and pwd strength
e7ab442 add: future features list
6b4be3b initial functions added
```
