# Usage

```
pwman <command> [arguments] [--db <path>]
```

Every command that touches the vault will prompt for your **master password**
(input is hidden). The vault file must use the `.pwv` extension.

## Command reference

| Command | Description |
|---------|-------------|
| `pwman init` | Create and initialize a new encrypted vault |
| `pwman add` | Add a new entry (interactive prompts) |
| `pwman get <name>` | Show a single entry in a table |
| `pwman list` | Browse all entries in an interactive UI |
| `pwman del <name>` | Delete an entry (asks for confirmation) |
| `pwman gen [length]` | Generate a random password (no vault needed) |
| `pwman totp <name>` | Show a live TOTP code for an entry |
| `pwman totp add <name>` | Attach a TOTP secret to an entry |
| `pwman totp del <name>` | Remove TOTP from an entry |
| `pwman export [csv\|xml] [path]` | Export all entries to a file |
| `pwman import <file.csv>` | Import entries from a CSV file |
| `pwman config [db <path>]` | Show or set the default vault path |
| `pwman --help` | Show usage |

## Getting started

```bash
pwman init                 # choose a master password (entered twice)
pwman add                  # add your first entry
pwman list                 # browse everything
```

### Add an entry

`pwman add` prompts for the name, username, password, URL and notes. **Leave the
password blank to auto-generate** a strong one; its strength is reported.

### Retrieve one entry

```bash
pwman get github
```

```
+----------+--------------------+
| Field    | Value              |
+----------+--------------------+
| Name     | github             |
| Username | user@example.com   |
| Password | s3cur3Pa$$w0rd!    |
| URL      | https://github.com |
| Notes    | personal account   |
+----------+--------------------+
```

### Generate a password

```bash
pwman gen        # 20 characters (default)
pwman gen 32     # custom length (10–128)
```

## The interactive `list` UI

`pwman list` opens a full-screen terminal table (powered by
[FTXUI](https://github.com/ArthurSonzogni/FTXUI)) with **Name · Username ·
Password · TOTP** columns.

- Passwords are shown as a **fixed-length `*` mask** — the width is constant, so
  it never reveals how long a password actually is.
- Entries with TOTP show a **live, zero-padded code and countdown** that refresh
  as the time-step rolls over.

### Keybindings

| Key | Action |
|-----|--------|
| `↑` / `↓` or `k` / `j` | Move the selection |
| `r` / `Enter` | Reveal the selected password |
| `c` | Copy the selected password to the clipboard |
| `t` | Copy the selected entry's current TOTP code |
| `/` | Search / filter by name or username |
| `Esc` | Clear the active search |
| `q` / `Esc` | Quit |

## Two-factor codes (TOTP)

Attach an RFC 6238 TOTP secret (raw Base32) to an existing entry:

```bash
pwman totp add github        # paste the Base32 secret when prompted
pwman totp github            # show a live, self-updating code
pwman totp del github        # remove it
```

Codes are copied to the clipboard automatically and the clipboard is cleared when
you quit the live view. See [Configuration](configuration.md) for choosing which
vault these act on.

> **Note:** `otpauth://` URIs are not parsed yet — provide the raw Base32 secret.
> Code generation currently uses HMAC-SHA1 (the RFC 6238 default).

## Exporting

```bash
pwman export                 # CSV -> pwman-export.csv
pwman export xml             # XML -> pwman-export.xml
pwman export csv backup.csv  # choose the output path
```

Exports contain your passwords in **plaintext** — see [Export](export.md).

## Importing

```bash
pwman import contacts.csv
```

Reads a CSV in the same column layout as the export. Entries whose name already
exists are skipped, so importing the same file twice is safe. See
[Export & Import](export.md#importing-csv) for the accepted format.

## Choosing the vault

- One-off: `pwman <command> --db /path/to/vault.pwv`
- Persistent default: `pwman config db /path/to/vault.pwv`

Details in [Configuration](configuration.md).
