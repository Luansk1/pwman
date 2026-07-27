# pwman — Progress

_Last updated: 2026-07-17_

A secure command-line password manager written in C++17. The whole database is now
encrypted at rest with **SQLCipher**, with XChaCha20-Poly1305 (libsodium) field encryption
layered on top, all protected by a single Argon2id-derived master password. Includes
RFC 6238 TOTP (2FA) support with a live, self-updating code display.

## Latest Change — CSV import (2026-07-25)

- **`cmd_import`** (`commands.cpp`): `pwman import <file.csv>` reads the CSV export format
  and adds entries. Includes a from-scratch RFC 4180 parser (`parse_csv`) handling quoted
  fields, escaped `""`, and embedded commas/newlines.
- **Column mapping**: header-based when the first row has `name`/`password` (columns may be
  a subset or reordered; only `name` required), else positional in export order.
- **TOTP**: a non-empty `totp_secret` (validated Base32) is attached with
  `totp_algorithm`/`digits`/`period` (defaults SHA1/6/30); invalid secrets skipped w/ warning.
- **Duplicates skipped** (name already exists); prints imported/with-TOTP/skipped/failed
  counts. Decrypted CSV content and row cells `secure_zero`'d after import.
- Wired in `main.cpp` + `commands.h` + usage text. Verified: export→import→re-export diff is
  **identical** (lossless, incl. TOTP and quoted fields); re-import skips all as duplicates;
  subset/positional/embedded-newline cases and missing-file error all pass. 88 tests pass.
- Docs updated (`docs/usage.md`, `docs/export.md` import section, README).

## Latest Change — export, config, and documentation (2026-07-21)

- **Export** (`cmd_export`, `commands.cpp`): `pwman export [csv|xml] [path]` decrypts all
  entries + TOTP config and writes a file (RFC 4180 CSV or escaped XML), `0600`, with a
  plaintext warning; secrets zeroed after write. Fixed a pre-existing compile error (a stray
  `;` broke the `print_usage` `<<` chain) and the stub that printed raw `ListItem`s.
- **Config / default vault path**: new `configured_db_path()` resolves `--db` > `PWMAN_DB`
  env > `~/.pwman/config` (`db=` line) > built-in default. `pwman config [db <path>|clear]`
  manages the stored default (`database.cpp` config helpers, `cmd_config`, `main.cpp` wiring).
- **Status flash fix** (`list_ui.cpp`): "Copied …" messages now expire via a timestamp
  (`flash_status`) instead of a blocking `sleep`, so the UI never freezes.
- **Docs**: new `docs/` set — installation, usage, configuration, architecture, export,
  development (+ index). README rewritten as a modern landing page with badges (license,
  C++17, CMake, platforms, tests, coverage, encryption), quick start, and a UI preview.
- **Test coverage**: measured with Clang source-based coverage — ~66% line coverage of the
  unit-tested core modules (base32/crypto/database/hmac/terminal). CLI/TUI/totp are covered
  by manual integration testing. Reproduction documented in `docs/development.md`.
- `.gitignore`: added `build-cov/`, coverage artifacts, `*.pwv`, `pwman-export.*`.

## Latest Change — list UI fixes: TOTP padding, search, TOTP copy (2026-07-19)

- **TOTP zero-padding fix** (`totp.cpp`): `totp_generate` now left-pads to `digits` and uses an
  integer power of ten instead of `std::pow`. Codes with leading zeros were printing short
  (e.g. `48290` instead of `048290`); combined with row clipping this looked like "zeros cut
  off the end". All codes are now exactly `digits` wide.
- **No column clipping** (`list_ui.cpp`): Name/Username columns capped (`kNameMax`/`kUserMax`,
  20) so a long value can't push the TOTP column off the right edge.
- **Copy TOTP** from the list: `t` copies the selected entry's current code (raw digits, no
  spacing) to the clipboard.
- **Search/filter**: `/` opens a search bar; typing filters rows by name or username
  (case-insensitive); `Esc` clears, `Enter` keeps the filter and returns to navigation. Header
  shows `(matched/total entries)`.
- **Non-interactive TOTP** (`commands.cpp`): `live_totp_display` now prints a single code and
  returns when stdin isn't a TTY, instead of spinning on pipe EOF — fixes the latent hang and
  makes `totp add`/`totp` scriptable.
- **Test vault generator**: `scripts/gen_test_vault.sh` builds a sample `.pwv` (10 entries, 4
  with TOTP; master `test1234`). Verified end-to-end over a PTY: search, reveal, TOTP copy
  (6-digit), live countdown, clean quit. 88 tests still pass.

## Latest Change — Interactive `list` UI with FTXUI (2026-07-19)

- **FTXUI** (v7.0.1) pulled in via CMake `FetchContent` (examples/docs/tests off). Linked
  `PRIVATE` to `pwman_lib`; propagates to the executable since the lib is static.
- New module **`src/list_ui.cpp` / `includes/list_ui.h`** (`run_list_ui`, `VaultRow`). `list`
  now opens a full-screen navigable table with **Name · Username · Password · TOTP** columns
  instead of the old plaintext table.
  - Passwords rendered as a **fixed-width `*` mask** (8 chars, `kMaskWidth`) so the display
    leaks nothing about real length; `r`/`Enter` reveals the selected one, `c` copies it.
  - Entries with TOTP show a **live** code + countdown; a background ticker thread posts a
    repaint event ~4×/sec.
  - Keys: `↑`/`↓` or `j`/`k` move, `r`/`Enter` reveal, `c` copy, `q`/`Esc` quit.
- `cmd_list` now derives the field key and decrypts each entry (+ its TOTP secret) into
  `VaultRow`s, runs the UI, then `secure_zero`s all held secrets.
- **Refactor**: `copy_to_clipboard` moved from a `commands.cpp` static into `terminal.{h,cpp}`
  (`pwman::copy_to_clipboard`), now shared by the TOTP view and the list UI.
- Verified over a PTY: table renders both entries, mask shows, arrow-nav + reveal + clipboard
  copy work, live TOTP countdown renders, `q` exits cleanly (rc 0). All 88 unit tests pass.
- Latent (pre-existing, not triggered in real tty use): `live_totp_display` mixes buffered
  `std::cin` with raw `read()` and loops forever on stdin EOF — only bites under piped input.

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
