# Export

`pwman export` writes every entry to a file, in **CSV** (default) or **XML**.

```bash
pwman export                 # CSV -> ./pwman-export.csv
pwman export xml             # XML -> ./pwman-export.xml
pwman export csv out.csv     # CSV -> ./out.csv
pwman export xml out.xml     # XML -> ./out.xml
```

`xml` / `csv` may also be written as `--xml` / `--csv`. Any other argument is
treated as the output path.

> ⚠️ **Security warning.** An export contains your passwords (and TOTP secrets) in
> **plaintext**. The file is created with `0600` permissions, but you should move
> it somewhere safe or delete it as soon as you're done. `pwman` prints this
> reminder after every export.

## CSV format

RFC 4180 compliant: fields containing a comma, quote, or newline are wrapped in
double quotes, and embedded quotes are doubled. Columns:

```
name,username,password,url,notes,totp_secret,totp_algorithm,totp_digits,totp_period
```

Example:

```csv
name,username,password,url,notes,totp_secret,totp_algorithm,totp_digits,totp_period
aws,admin,aws-R00t-key-000,https://console.aws.amazon.com,"root, danger",GEZDGNBVGY3TQOJQ,SHA1,6,30
github,octocat@example.com,Gh!tHub_p4ss,https://github.com,personal,,,,
```

Entries without TOTP leave the four `totp_*` columns empty.

## XML format

```xml
<?xml version="1.0" encoding="UTF-8"?>
<pwman-export>
  <entry>
    <name>aws</name>
    <username>admin</username>
    <password>aws-R00t-key-000</password>
    <url>https://console.aws.amazon.com</url>
    <notes>root, danger</notes>
    <totp secret="GEZDGNBVGY3TQOJQ" algorithm="SHA1" digits="6" period="30"/>
  </entry>
  <entry>
    <name>github</name>
    <username>octocat@example.com</username>
    <password>Gh!tHub_p4ss</password>
    <url>https://github.com</url>
    <notes>personal</notes>
  </entry>
</pwman-export>
```

Special characters (`&`, `<`, `>`, `"`, `'`) are XML-escaped. The `<totp>`
element is present only for entries that have TOTP configured.

## Importing (CSV)

```bash
pwman import backup.csv
```

Import reads a CSV using the **same columns as the CSV export**. It is the exact
inverse of `pwman export csv`, so an export/import round-trip is lossless
(including TOTP secrets).

- **Header row:** if the first row contains a `name`/`password` header, columns
  are matched by title — so you can omit columns or reorder them. Only `name` is
  required; `password`, `username`, `url`, `notes` and the `totp_*` columns are
  optional. Without a header, columns are read positionally in export order.
- **Quoting:** RFC 4180 is fully supported — fields may contain commas, quotes
  (escaped as `""`) and newlines when wrapped in double quotes.
- **Duplicates:** an entry whose `name` already exists is **skipped** (never
  overwritten), so re-running an import is safe.
- **TOTP:** a non-empty `totp_secret` (Base32) is attached to the new entry,
  using `totp_algorithm` / `totp_digits` / `totp_period` when present (defaults:
  `SHA1` / `6` / `30`). An invalid secret is skipped with a warning; the entry
  itself is still imported.

`pwman import` prints a summary, e.g.:

```
[+] Imported 8 entries (3 with TOTP).
[*] 2 skipped (an entry with that name already exists).
```

> Since the source CSV holds passwords in plaintext, delete it once the import
> is done.

