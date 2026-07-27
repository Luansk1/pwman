# Development

## Project layout

```
pwman/
├── CMakeLists.txt          # Build configuration
├── includes/               # Public headers
│   ├── crypto.h            # Key derivation & field encryption
│   ├── database.h          # SQLCipher storage + config path resolution
│   ├── terminal.h          # Hidden input, tables, clipboard
│   ├── commands.h          # CLI command entry points
│   ├── list_ui.h           # Interactive list UI (FTXUI)
│   ├── base32.h            # RFC 4648 Base32
│   ├── totp.h              # RFC 6238 TOTP
│   └── hmac.h              # SHA-1 / HMAC
├── src/                    # Implementations
│   ├── main.cpp            # Entry point & argument parsing
│   ├── crypto.cpp          # libsodium wrapper (Argon2id, XChaCha20-Poly1305)
│   ├── database.cpp        # SQLCipher operations, vault format, config file
│   ├── terminal.cpp        # Terminal I/O
│   ├── commands.cpp        # init/add/get/list/del/gen/totp/export/config
│   ├── list_ui.cpp         # FTXUI table, search, reveal, TOTP copy
│   ├── base32.cpp
│   ├── totp.cpp
│   └── hmac.cpp
├── tests/                  # GoogleTest suites
├── scripts/
│   └── gen_test_vault.sh   # Generate a sample vault for manual testing
└── docs/                   # This documentation
```

The build produces a static library `pwman_lib` (shared by the executable and the
tests), the `pwman` executable, and the `pwman_tests` test runner.

## Building

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

Useful options:
- `-DBUILD_TESTS=OFF` — skip the test suite (and the GoogleTest fetch).

FTXUI and GoogleTest are pulled in with CMake `FetchContent` — the first configure
needs network access.

## Running the tests

```bash
cd build
ctest --output-on-failure
```

The suite (88 tests) covers the core modules:

- Encryption / decryption round trips and tamper detection (`crypto`)
- Key-derivation consistency
- Database CRUD, schema init, salt & verify-token round trips
- Base32 encode / decode / validate
- HMAC-SHA1 / SHA-256 / SHA-512 against RFC test vectors
- Table-formatting output

## Test coverage

Line coverage of the modules exercised by the unit tests (`base32`, `crypto`,
`database`, `hmac`, `terminal`) is **~66%**. The CLI glue (`commands.cpp`,
`main.cpp`), the terminal UI (`list_ui.cpp`) and `totp.cpp` are currently
validated by manual / integration testing rather than unit tests.

Reproduce with Clang source-based coverage:

```bash
cmake -S . -B build-cov -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate"
cmake --build build-cov --target pwman_tests

LLVM_PROFILE_FILE=build-cov/pwman.profraw ./build-cov/pwman_tests
llvm-profdata merge -sparse build-cov/pwman.profraw -o build-cov/pwman.profdata
llvm-cov report ./build-cov/pwman_tests -instr-profile=build-cov/pwman.profdata src/*.cpp
```

(On macOS prefix the `llvm-*` tools with `xcrun`.)

## Manual testing

`scripts/gen_test_vault.sh` builds a throwaway vault with sample data (10 entries,
several with TOTP) so you can exercise the UI, search, export and config without
touching a real vault:

```bash
scripts/gen_test_vault.sh test-vault.pwv    # master password: test1234
pwman --db test-vault.pwv list
```

## Coding conventions

- C++17, no exceptions across module boundaries except the typed
  `CryptoError` / `DatabaseError` / `TotpError`.
- Zero sensitive buffers with `secure_zero` / `sodium_memzero` as soon as they
  are no longer needed.
- Keep new terminal/system helpers in `terminal.*` so they can be shared.
