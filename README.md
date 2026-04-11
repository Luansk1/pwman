# pwman - Command Line Password Manager

A secure command-line password manager written in C++17. Passwords are encrypted with XChaCha20-Poly1305 (via libsodium) and stored in a local SQLite database, protected by a master password derived using Argon2id.

## Features

- **Strong encryption**: XChaCha20-Poly1305 authenticated encryption for all stored data
- **Secure key derivation**: Argon2id with moderate parameters (via `crypto_pwhash`)
- **Local storage**: SQLite database, no network access required
- **Hidden input**: Master password and entry passwords are never shown during input
- **Password generator**: Built-in cryptographically secure random password generation
- **Cross-platform**: Works on Linux, macOS, and Windows

## Features coming soon
- **TOTP Support**
- **Entropie calculation**

## Security Design

```
Master Password
      |
      v
  Argon2id (salt stored in DB)
      |
      v
  256-bit Key
      |
      v
  XChaCha20-Poly1305
      |
      v
  Encrypted entries in SQLite
```

- The master password is never stored. A verification token (`"pwman_verify"`) is encrypted and stored; on unlock, the token is decrypted to verify the password.
- Each field (username, password, URL, notes) is encrypted independently with a unique random nonce.
- Entry names are stored in plaintext so that `list` works without unlocking.
- Sensitive memory (keys, decrypted passwords) is zeroed using `sodium_memzero`.

## TOTP Flow

## Dependencies

- **libsodium** >= 1.0.18
- **SQLite3** >= 3.30
- **CMake** >= 3.16
- **pkg-config**
- A C++17-capable compiler (GCC 8+, Clang 7+, MSVC 2019+)

### Install dependencies

**macOS (Homebrew):**
```bash
brew install libsodium sqlite pkg-config cmake
```

**Ubuntu/Debian:**
```bash
sudo apt install libsodium-dev libsqlite3-dev pkg-config cmake g++
```

**Arch Linux:**
```bash
sudo pacman -S libsodium sqlite pkg-config cmake
```

**Windows (vcpkg):**
```powershell
vcpkg install libsodium sqlite3
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

Creates a new encrypted database at `~/.pwman/pwman.db` and sets the master password.

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

Shows all entry names (no master password required).

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
