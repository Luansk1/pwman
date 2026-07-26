#!/usr/bin/env bash
#
# Generate a pwman test vault populated with sample data, for trying out the
# `list` UI (search, reveal, TOTP copy, live codes) without touching your real
# vault. Safe to re-run: it recreates the vault from scratch each time.
#
# Usage:
#   scripts/gen_test_vault.sh [output.pwv]
#
# Then explore it with:
#   ./build/pwman --db test-vault.pwv list
#
# Master password for the generated vault: "test1234"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${PWMAN_BIN:-$REPO_ROOT/build/pwman}"
VAULT="${1:-$REPO_ROOT/test-vault.pwv}"
MASTER="test1234"

if [[ ! -x "$BIN" ]]; then
  echo "error: pwman binary not found at '$BIN' — build it first (cmake --build build)." >&2
  echo "       or set PWMAN_BIN=/path/to/pwman" >&2
  exit 1
fi

# Fresh start: remove the vault and any SQLite sidecar files.
rm -f "$VAULT" "$VAULT"-wal "$VAULT"-shm "$VAULT"-journal

# init: master password entered twice.
printf '%s\n%s\n' "$MASTER" "$MASTER" | "$BIN" --db "$VAULT" init >/dev/null

# add <name>: master, name, username, password (empty = generate), url, notes.
add_entry() {
  local name="$1" user="$2" pass="$3" url="$4" notes="$5"
  printf '%s\n%s\n%s\n%s\n%s\n%s\n' \
    "$MASTER" "$name" "$user" "$pass" "$url" "$notes" \
    | "$BIN" --db "$VAULT" add >/dev/null
}

# totp add <name>: master, then the Base32 secret. Stdin is a pipe here, so the
# live display prints one code and returns (no interactive loop).
add_totp() {
  local name="$1" secret="$2"
  printf '%s\n%s\n' "$MASTER" "$secret" | "$BIN" --db "$VAULT" totp add "$name" >/dev/null
}

add_entry "github"     "octocat@example.com"   "Gh!tHub_p4ss0"          "https://github.com"        "personal account"
add_entry "gitlab"     "octo@example.com"      "gL4b#secret00"          "https://gitlab.com"        ""
add_entry "aws"        "admin"                 "aws-R00t-key-000"       "https://console.aws.amazon.com" "root, danger"
add_entry "gmail"      "jane.doe@gmail.com"    "sup3rSecretMail!"       "https://mail.google.com"   "recovery: 555-0100"
add_entry "proton"     "jane@proton.me"        "0protonPass0"           "https://mail.proton.me"    "e2e mail"
add_entry "bank"       "jdoe"                  "N0t-my-r34l-pin-0"      "https://examplebank.com"   "checking"
add_entry "reddit"     "u/janedoe"             "r3dd1t_thr0waway"       "https://reddit.com"        ""
add_entry "netflix"    "jane.doe@gmail.com"    ""                       "https://netflix.com"       "family plan (auto-generated pw)"
add_entry "server-ssh" "root@10.0.0.5"         "id_ed25519-passphrase0" "ssh://10.0.0.5"            "prod box"
add_entry "router"     "admin"                 "admin0admin0"           "http://192.168.1.1"        "LAN gateway"

# A few entries with TOTP (RFC 6238 test-style Base32 secrets).
add_totp "github" "JBSWY3DPEHPK3PXP"
add_totp "aws"    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
add_totp "gmail"  "KRSXG5CTMVRXEZLU"
add_totp "bank"   "NB2W45DFOIZA"

echo "Test vault created: $VAULT"
echo "Master password:    $MASTER"
echo
echo "Try it:"
echo "  $BIN --db \"$VAULT\" list"
