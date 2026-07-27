# Installation

## Requirements

| Dependency | Version | Notes |
|------------|---------|-------|
| A C++17 compiler | GCC 8+, Clang 7+, MSVC 2019+ | |
| [CMake](https://cmake.org) | ≥ 3.16 | Build system |
| [pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/) | any | Locates libsodium & SQLCipher |
| [libsodium](https://doc.libsodium.org/) | ≥ 1.0.18 | Argon2id + XChaCha20-Poly1305 |
| [SQLCipher](https://www.zetetic.net/sqlcipher/) | ≥ 4.0 | Full-database encryption (drop-in `<sqlite3.h>`) |

Two more dependencies — [FTXUI](https://github.com/ArthurSonzogni/FTXUI) (terminal UI)
and [GoogleTest](https://github.com/google/googletest) (tests) — are fetched
automatically by CMake at configure time, so **the first configure needs network access**.

## Install the system dependencies

**macOS (Homebrew):**
```bash
brew install libsodium sqlcipher pkg-config cmake
```

**Ubuntu / Debian:**
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

## Download & build

```bash
git clone https://github.com/Luansk1/pwman.git
cd pwman
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The binary is produced at `build/pwman`.

> Tip: pass `-DBUILD_TESTS=OFF` to skip building the GoogleTest suite (and the
> GoogleTest download) for a faster first build.

## Install into your `PATH`

So you can run `pwman` from anywhere instead of `./build/pwman`:

### Option A — symlink (recommended for development)

A symlink tracks your build output, so a rebuild instantly updates the command:

```bash
ln -sf "$(pwd)/build/pwman" /opt/homebrew/bin/pwman   # Apple Silicon
# or, on Linux / Intel Mac:
ln -sf "$(pwd)/build/pwman" /usr/local/bin/pwman
```

Rebuild with `cmake --build build` and `pwman` is immediately the new version.
(Don't delete the `build/` directory — the symlink points into it.)

### Option B — install a copy

```bash
cmake --install build --prefix /opt/homebrew    # or /usr/local
```

This copies the binary to `<prefix>/bin/pwman`. Re-run it after each rebuild to update.

## Verify

```bash
pwman --help
```

## Next steps

- Create your first vault and add entries: [Usage](usage.md)
- Keep a vault somewhere other than the default location: [Configuration](configuration.md)
