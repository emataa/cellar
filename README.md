# pwmanager

A CLI password manager that encrypts your passworcs with Argon2id (key derivation) + AES-256-GCM (authenticated encryption). No cloud or no browser extension required.

## How it works

- Your master password is never stored. It's run through Argon2id with a random salt to derive a 32-byte AES key.
- That key encrypts a JSON blob of your entries (username, password, url, notes) with AES-256-GCM, which also detects tampering. If the vault file is modified, decryption fails loudly instead of silently returning garbage.
- Saves are atomic (write to a temp file, fsync, rename) and durable, so a crash mid-write can't corrupt the vault. A file lock stops two `pv` processes from racing on the same vault.
- Vault lives at `~/.password-vault/vault.json` by default, mode `0600` (owner read/write only).

## Why Argon2id + AES-256-GCM

**Argon2id** turns your master password into the encryption key. Passwords alone are short and guessable — anyone who stole the vault file could try millions of common passwords per second. Argon2id slows that down on purpose: deriving the key costs real time and memory (64 MiB). You pay that cost once, when unlocking. An attacker pays it for every single guess, which makes brute-forcing impractical.

**AES-256-GCM** does the encrypting. Besides scrambling the data so it's unreadable without the key, it seals the file so any tampering is detectable. Edit the encrypted file, even one byte, and it refuses to decrypt instead of producing corrupted or misleading data.

The random values used during encryption (the salt for Argon2id, the nonce for AES-GCM) are stored alongside the encrypted data in the vault file. That's normal — they're not secret on their own, they just need to be unique.

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv) — package manager
- [just](https://github.com/casey/just) — command runner

## Install

```bash
git clone <repo-url>
cd pwmanager
./install.sh
```

`install.sh` checks for Python 3.13+, installs `uv` and `just` if missing, then runs `just setup` to create the venv and install dependencies.

Or manually:

```bash
just setup
```

## Usage

All commands go through `just run --`, or directly via `pv` once the venv is activated.

```bash
just run -- init                          # create a new vault
just run -- add github                    # add an entry (prompts for fields)
just run -- add github --generate         # add with a generated password
just run -- get github                    # show an entry
just run -- list                          # list all entry names
just run -- delete github                 # remove an entry
just run -- change-password               # rotate the master password
just run -- gen 32                        # print a random password (no vault touched)
```

Every command that touches the vault prompts for your master password interactively — never as a CLI flag, since that would leak into shell history and `ps`.

By default the vault path is `~/.password-vault/vault.json`. Override with `--vault <path>` or the `PV_VAULT` environment variable.

### Examples

```bash
# Custom vault location
just run -- --vault ~/work-vault.json init

# Generate a 32-char password with no symbols
just run -- gen 32 --no-symbols

# Pipe a generated password elsewhere
PASSWORD=$(just run -- gen 24)
```

## Development

```bash
just test         # run the test suite
just test-cov      # with coverage report
just lint          # ruff + pylint + mypy
just format        # auto-format with yapf
just fix           # auto-fix what ruff can
just clean         # remove venv and build/cache artifacts
```

## Project layout

```
pwmanager/
├── pwmanager/          # package
│   ├── main.py         # CLI commands (Typer)
│   ├── vault.py        # vault file format, atomic writes, entry CRUD
│   ├── crypto.py        # Argon2id + AES-256-GCM
│   ├── generator.py     # random password generation
│   └── constants.py     # config, prompts, messages
├── pyproject.toml
├── justfile
└── install.sh
```

## Security notes

- Master password minimum length: 8 characters, enforced on `init` and `change-password`.
- KDF parameters (Argon2id time/memory/parallelism cost) are stored per-vault, so upgrading the defaults later doesn't break old vaults.
- `change-password` re-encrypts the entire vault under a fresh salt and key, not just a password check.
