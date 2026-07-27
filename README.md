<div align="center">

# 🔐 pwman

**A secure, command-line password manager for your terminal.**

Fully-encrypted local vault · two-factor (TOTP) codes · an interactive TUI — all in a single C++17 binary.

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](CHANGELOG.md)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![Build: CMake](https://img.shields.io/badge/build-CMake-064F8C.svg?logo=cmake&logoColor=white)](CMakeLists.txt)
[![Platforms](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](docs/installation.md)
[![Tests](https://img.shields.io/badge/tests-88%20passing-brightgreen.svg)](docs/development.md)
[![Coverage](https://img.shields.io/badge/coverage-66%25-yellow.svg)](docs/development.md#test-coverage)
[![Encryption](https://img.shields.io/badge/encryption-SQLCipher%20%2B%20libsodium-8A2BE2.svg)](docs/architecture.md)

</div>

---

`pwman` keeps your credentials in a single **SQLCipher-encrypted** vault file, with a
second layer of **XChaCha20-Poly1305** field encryption on top — both unlocked by one
master password derived with **Argon2id**. Browse everything in a live terminal UI, with
built-in TOTP two-factor codes and CSV/XML export.

## ✨ Features

- 🔒 **Full-database encryption** — the entire vault (structure *and* values) is opaque at rest via SQLCipher, with per-field XChaCha20-Poly1305 as defence in depth.
- 🔑 **Strong key derivation** — Argon2id for the field key; the master password is never stored.
- 🖥️ **Interactive TUI** — browse, search, reveal, and copy from a full-screen [FTXUI](https://github.com/ArthurSonzogni/FTXUI) table.
- ⏱️ **Two-factor (TOTP)** — RFC 6238 codes with a live, self-updating display and clipboard copy.
- 🎭 **Length-hiding masks** — passwords render as a fixed-width `*` so the display leaks nothing about their length.
- 🎲 **Password generator** — cryptographically secure, with strength feedback.
- 📤 **Import / export** — CSV import and CSV/XML export, with a lossless round-trip.
- 🗂️ **Flexible vault location** — per-command `--db`, a `PWMAN_DB` env var, or a saved default.
- 💻 **Cross-platform** — Linux, macOS, and Windows.

## 🚀 Quick start

```bash
# 1. Install dependencies (macOS shown; see docs for Linux/Windows)
brew install libsodium sqlcipher pkg-config cmake

# 2. Build
git clone https://github.com/Luansk1/pwman.git
cd pwman
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# 3. (optional) put it on your PATH
ln -sf "$(pwd)/build/pwman" /usr/local/bin/pwman

# 4. Use it
pwman init          # create your vault + master password
pwman add           # add an entry
pwman list          # browse in the interactive UI
```

> First build fetches FTXUI + GoogleTest via CMake, so it needs network access.
> Full instructions (all platforms, install options): **[docs/installation.md](docs/installation.md)**.

## 🎬 The `list` UI

```
╭──────────────────── pwman — vault (3/10 entries) ────────────────────╮
│ Name       Username             Password   TOTP                       │
│ ─────────  ──────────────────   ────────   ───────────────            │
│ aws        admin                ********    576 163  (18s)            │
│ github     octocat@example.com  ********    405 830  (18s)            │
│ gmail      jane.doe@gmail.com   ********    —                         │
├───────────────────────────────────────────────────────────────────────┤
│ ↑/↓ move · r reveal · c copy pw · t copy TOTP · / search · q quit      │
╰───────────────────────────────────────────────────────────────────────╯
```

`↑/↓` move · `r` reveal · `c` copy password · `t` copy TOTP · `/` search · `q` quit.

## 📚 Documentation

| Guide | Description |
|-------|-------------|
| [Installation](docs/installation.md) | Dependencies, building, installing to your `PATH` |
| [Usage](docs/usage.md) | Every command and the interactive UI |
| [Configuration](docs/configuration.md) | Default vault, `PWMAN_DB`, `--db` |
| [Architecture](docs/architecture.md) | Encryption layers, vault format, threat model |
| [Export & Import](docs/export.md) | CSV/XML export and CSV import formats |
| [Development](docs/development.md) | Project layout, tests, coverage |

## 🛡️ Security at a glance

- **Two layers, one password:** SQLCipher encrypts the whole file; libsodium encrypts each field.
- **Never stored:** the master password is verified against an encrypted token, compared in constant time.
- **Recognition magic:** vaults carry `application_id = 0x50574D31` (`PWM1`) so pwman only opens its own files.
- **Hygiene:** keys and plaintext are wiped with `sodium_memzero`; the vault file is `0600`.

Full details and threat model in **[docs/architecture.md](docs/architecture.md)**.

## 🧪 Testing

```bash
cd build
ctest --output-on-failure
```

88 GoogleTest cases cover the crypto, storage, Base32, HMAC and terminal modules.
See **[docs/development.md](docs/development.md)** for coverage measurement.

## 📝 Changelog

Notable changes are recorded in [CHANGELOG.md](CHANGELOG.md), following
[Semantic Versioning](https://semver.org).

## 📄 License

Released under the [MIT License](LICENSE).
