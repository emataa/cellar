# cellar

A CLI password manager that encrypts your passwords with Argon2id (key derivation) + AES-256-GCM (authenticated encryption). No cloud or no browser extension required.

## Disclaimer

This is a personal project that still may have security flaws. Don't use it for anything commercial or to store credentials you can't afford to lose. Consider using other well-documented password managers such as 1password.

## How it works

- Your master password is never stored. It's run through Argon2id with a random salt to derive a 32-byte AES key.
- That key encrypts a JSON blob of your entries (username, password, url, notes) with AES-256-GCM, which also detects tampering. If the vault file is modified, decryption fails with an authentication error instead of returning corrupted data.
- Saves are atomic (write to a temp file, fsync, rename) and durable, so a crash mid-write can't corrupt the vault. A file lock stops two `pv` processes from racing on the same vault.
- Vault lives at `~/.password-vault/vault.json` by default, mode `0600` (owner read/write only).

## Why Argon2id + AES-256-GCM

**Argon2id** is a memory-hard key derivation function that won the 2015 Password Hashing Competition. It turns the master password into the encryption key. On its own, a password is short enough that an attacker who steals the vault file could try millions of guesses per second against it. Argon2id makes each guess cost real time and memory (64 MiB), which is what makes brute-forcing impractical.

**AES-256-GCM** is AES with a 256-bit key, run in a mode that both encrypts and authenticates the data. Besides making the data unreadable without the key, it detects tampering: modifying even one byte of the encrypted file makes decryption fail.

The random values used during encryption (the salt for Argon2id, the nonce for AES-GCM) are stored alongside the encrypted data in the vault file. They aren't secret on their own; they still need to be unique.

## Requirements

- Python 3.13+
- [uv](https://docs.astral.sh/uv) — package manager
- [just](https://github.com/casey/just) — command runner

## Install

```bash
git clone
cd cellar
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
just run -- init                            # create a new vault
just run -- add your_entry                  # add an entry (prompts for fields)
just run -- add your_entry --generate       # add with a generated password
just run -- get your_entry                  # show an entry
just run -- list                            # list all entry names
just run -- delete your_entry               # remove an entry
just run -- change-password                 # rotate the master password
just run -- gen 32                          # print a random password (no vault touched)
```

Every command that touches the vault prompts for your master password interactively, never as a CLI flag since that would leak into shell history and `ps`.

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

## Security notes

- Master password minimum length: 8 characters, enforced on `init` and `change-password`.
- KDF parameters (Argon2id time/memory/parallelism cost) are stored per-vault, so upgrading the defaults later doesn't break old vaults.
- `change-password` re-encrypts the entire vault under a fresh salt and key.

## Future plans

- GUI client for the vault
