# pwman - Command Line Password Manager

A secure command-line password manager written in C++17. The entire database is encrypted at rest with **SQLCipher**, and individual fields are additionally sealed with XChaCha20-Poly1305 (via libsodium) as defence in depth. Everything is protected by a single master password derived using Argon2id.

## Features

- **Full-database encryption**: SQLCipher encrypts the whole SQLite file — table names, indexes and structure are opaque at rest, not just the values
- **Layered field encryption**: XChaCha20-Poly1305 authenticated encryption for each stored field on top of the SQLCipher layer
- **Secure key derivation**: Argon2id with moderate parameters (via `crypto_pwhash`)
- **Custom vault format**: databases use the `.pwv` extension and carry a recognition magic in the SQLite header so pwman can positively identify its own vaults
- **Local storage**: single encrypted file, no network access required
- **Hidden input**: Master password and entry passwords are never shown during input
- **Password generator**: Built-in cryptographically secure random password generation
- **Cross-platform**: Works on Linux, macOS, and Windows

## Features coming soon
- **TOTP Support**
- **Entropie calculation**

## Security Design

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

- The same master password unlocks two independent layers: SQLCipher (whole-file, its KDF salt lives in the file's plaintext 16-byte header) and Argon2id (per-field, its salt is stored inside the now-encrypted database).
- The master password is never stored. A verification token (`"pwman_verify"`) is encrypted and stored; on unlock, the token is decrypted to verify the field key.
- Each field (username, password, URL, notes) is encrypted independently with a unique random nonce.
- Because the whole file is encrypted, **every** command — including `list` — now requires the master password. Entry names are no longer readable without unlocking.
- Vaults use the `.pwv` extension (the CLI refuses other file names) and set `PRAGMA application_id = 0x50574D31` ("PWM1") as a recognition magic, checked after decryption to confirm the file is a genuine pwman vault.
- Sensitive memory (keys, decrypted passwords) is zeroed using `sodium_memzero`.

## TOTP Flow

## Dependencies

- **libsodium** >= 1.0.18
- **SQLCipher** >= 4.0 (provides the `<sqlite3.h>` API with transparent encryption)
- **CMake** >= 3.16
- **pkg-config**
- A C++17-capable compiler (GCC 8+, Clang 7+, MSVC 2019+)

### Install dependencies

**macOS (Homebrew):**
```bash
brew install libsodium sqlcipher pkg-config cmake
```

**Ubuntu/Debian:**
```bash
sudo apt install libsodium-dev libsqlcipher-dev pkg-config cmake g++
```

**Arch Linux:**
```bash
sudo pacman -S libsodium sqlcipher pkg-config cmake
```

**Windows (vcpkg):**
```powershell
vcpkg install libsodium sqlcipher
```

## Build

```bash
mkdir build && cd build
cmake ..
cmake --build .
```

The binary is produced at `build/pwman`.

## Usage

### Initialize database

```bash
pwman init
```

Creates a new encrypted vault at `~/.pwman/pwman.pwv` and sets the master password.

### Add an entry

```bash
pwman add
```

Prompts for master password, then entry details (name, username, password, URL, notes). Leave the password empty to auto-generate one.

### Retrieve an entry

```bash
pwman get <name>
```

Displays the entry in a formatted table after master password verification.

```
+----------+-----------------------+
| Field    | Value                 |
+----------+-----------------------+
| Name     | github                |
| Username | user@example.com      |
| Password | s3cur3Pa$$w0rd!       |
| URL      | https://github.com    |
| Notes    | personal account      |
+----------+-----------------------+
```

### List all entries

```bash
pwman list
```

Shows all entry names. Requires the master password, since the whole database is encrypted.

### Delete an entry

```bash
pwman del <name>
```

Requires master password verification, then asks for confirmation.

### Generate a password

```bash
pwman gen [length]
```

Generates a random password (default: 20 characters). Does not require the database.

### Custom database path

```bash
pwman --db /path/to/custom.db <command>
```

## Testing

```bash
cd build
cmake --build .
ctest --output-on-failure
```

Tests cover:
- Encryption/decryption round trips
- Key derivation consistency
- Tamper detection (corrupted/truncated ciphertext)
- Database CRUD operations
- Table formatting output

## Project Structure

```
pwman/
├── CMakeLists.txt          # Build configuration
├── README.md               # This file
├── include/
│   ├── crypto.h            # Encryption & key derivation
│   ├── database.h          # SQLite storage layer
│   ├── terminal.h          # Terminal I/O utilities
│   └── commands.h          # CLI command implementations
├── src/
│   ├── main.cpp            # Entry point & argument parsing
│   ├── crypto.cpp          # libsodium wrapper
│   ├── database.cpp        # SQLite operations
│   ├── terminal.cpp        # Hidden input & table printing
│   └── commands.cpp        # Command logic (init/add/get/list/del/gen)
└── tests/
    ├── test_crypto.cpp     # Crypto module tests
    ├── test_database.cpp   # Database module tests
    └── test_terminal.cpp   # Terminal output tests
```

## License

See [LICENSE](LICENSE) file.
