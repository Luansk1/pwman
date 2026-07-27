# Configuration

By default, `pwman` uses the vault at **`~/.pwman/pwman.pwv`**. You can point it
at a vault stored anywhere — for a single command or permanently.

## Resolution order

When you run a command, the vault path is resolved in this priority order:

1. **`--db <path>`** on the command line (highest priority; per-command)
2. **`PWMAN_DB`** environment variable
3. **`db=` line** in the config file (`~/.pwman/config`)
4. **Built-in default** (`~/.pwman/pwman.pwv`)

## Per-command override

```bash
pwman list --db /media/usb/secrets.pwv
```

`--db` always wins, so you can temporarily work with a different vault without
changing your saved default.

## Persistent default (config file)

Use the `config` command to store a default so you never have to type `--db`:

```bash
pwman config db /media/usb/secrets.pwv   # set the default vault
pwman config                             # show current configuration
pwman config clear                       # forget the stored default
```

`pwman config` prints something like:

```
[*] Config file:   /Users/you/.pwman/config
Stored db:     /media/usb/secrets.pwv
PWMAN_DB env:  (unset)
Effective db:  /media/usb/secrets.pwv
```

Notes:
- The path must use the `.pwv` extension. A leading `~/` is expanded to your home
  directory.
- The config file is a simple `key=value` text file (`db=<path>`), stored `0600`.
- If the target file doesn't exist yet, run `pwman init` to create it.

## Environment variable

Handy for scripts or a per-shell default (it overrides the config file):

```bash
export PWMAN_DB=/media/usb/secrets.pwv
pwman list
```

Add the `export` line to your shell profile (`~/.zshrc`, `~/.bashrc`) to make it
persistent for that shell.
