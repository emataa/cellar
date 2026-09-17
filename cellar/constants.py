from pathlib import Path
from typing import Final

# =============================================================================
# Argon2id KDF parameters
# =============================================================================
# parallelism=4 instead of OWASP's server-oriented parallelism=1
# since this is a single-user local tool and the speedup helps the
# legit user more than it helps an attacker relative to cost.

ARGON2_TIME_COST: Final[int] = 3
ARGON2_MEMORY_KIB: Final[int] = 65536  # 64 MiB
ARGON2_PARALLELISM: Final[int] = 4
SALT_LENGTH_BYTES: Final[int] = 16

# Hard floors used to sanity-check params loaded from a vault file
# (Argon2 will crash with a confusing error below these).
ARGON2_TIME_COST_MIN: Final[int] = 1
ARGON2_PARALLELISM_MIN: Final[int] = 1
ARGON2_MEMORY_KIB_PER_LANE_MIN: Final[int] = 8


# =============================================================================
# AES-256-GCM parameters
# =============================================================================
KEY_LENGTH_BYTES: Final[int] = 32
NONCE_LENGTH_BYTES: Final[int] = 12  # NIST SP 800-38D recommended size


# =============================================================================
# Vault file format
# =============================================================================
# JSON envelope: {version, kdf: {...}, cipher: {...}}. KDF params are
# stored per-file (not hardcoded) so changing defaults doesn't break
# old vaults.

VAULT_FORMAT_VERSION: Final[int] = 1

VAULT_KEY_VERSION: Final[str] = "version"
VAULT_KEY_KDF: Final[str] = "kdf"
VAULT_KEY_CIPHER: Final[str] = "cipher"

KDF_KEY_NAME: Final[str] = "name"
KDF_KEY_SALT: Final[str] = "salt"
KDF_KEY_TIME_COST: Final[str] = "time_cost"
KDF_KEY_MEMORY_COST: Final[str] = "memory_cost"
KDF_KEY_PARALLELISM: Final[str] = "parallelism"

CIPHER_KEY_NAME: Final[str] = "name"
CIPHER_KEY_NONCE: Final[str] = "nonce"
CIPHER_KEY_CIPHERTEXT: Final[str] = "ciphertext"

KDF_NAME_ARGON2ID: Final[str] = "argon2id"
CIPHER_NAME_AES_256_GCM: Final[str] = "aes-256-gcm"

VAULT_FILE_MODE: Final[int] = 0o600  # owner rw only

DEFAULT_VAULT_DIRECTORY: Final[Path] = Path.home() / ".password-vault"
DEFAULT_VAULT_FILENAME: Final[str] = "vault.json"
DEFAULT_VAULT_PATH: Final[Path] = (
    DEFAULT_VAULT_DIRECTORY / DEFAULT_VAULT_FILENAME
)


# =============================================================================
# Password generator defaults
# =============================================================================
DEFAULT_GENERATED_PASSWORD_LENGTH: Final[int] = 24
MINIMUM_GENERATED_PASSWORD_LENGTH: Final[int] = 8
MINIMUM_MASTER_PASSWORD_LENGTH: Final[int] = 8  # NIST SP 800-63B floor

LOWERCASE_LETTERS: Final[str] = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_LETTERS: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS: Final[str] = "0123456789"

# Excludes quotes/backticks (copy-paste issues) and backslash/dollar
# (shell-eaten characters).
SAFE_SYMBOLS: Final[str] = "!@#$%^&*()-_=+[]{};:,.<>/?"


# =============================================================================
# CLI prompt and message strings
# =============================================================================
PROMPT_MASTER_PASSWORD: Final[str] = "Master password: "
PROMPT_MASTER_PASSWORD_NEW: Final[str] = "New master password: "
PROMPT_MASTER_PASSWORD_CONFIRM: Final[str] = "Confirm master password: "
PROMPT_ENTRY_PASSWORD: Final[str] = "Password for {entry}: "
PROMPT_ENTRY_USERNAME: Final[str] = "Username for {entry}: "
PROMPT_ENTRY_URL: Final[str] = "URL (optional, press Enter to skip): "
PROMPT_ENTRY_NOTES: Final[str] = "Notes (optional, press Enter to skip): "

MSG_VAULT_CREATED: Final[str] = "Vault created at {path}"
MSG_VAULT_ALREADY_EXISTS: Final[str] = "Vault already exists at {path}"
MSG_VAULT_NOT_FOUND: Final[str] = (
    "No vault at {path}. Run `pv init` to create one"
)
MSG_ENTRY_ADDED: Final[str] = "Added entry: {name}"
MSG_ENTRY_DELETED: Final[str] = "Deleted entry: {name}"
MSG_ENTRY_NOT_FOUND: Final[str] = "No entry named: {name}"
MSG_ENTRY_ALREADY_EXISTS: Final[str] = (
    "Entry already exists: {name}. Use --force to overwrite"
)
MSG_PASSWORDS_DO_NOT_MATCH: Final[str] = "Passwords did not match"
MSG_WRONG_MASTER_PASSWORD: Final[str] = (
    "Wrong master password (or vault file is corrupted)"
)
MSG_VAULT_EMPTY: Final[str] = "Vault is empty. Add an entry with `pv add`"

MSG_MASTER_PASSWORD_EMPTY: Final[str] = "Master password cannot be empty"
MSG_MASTER_PASSWORD_TOO_SHORT: Final[str] = (
    "Master password must be at least {minimum} characters"
)
MSG_MASTER_PASSWORD_CHANGED: Final[str] = (
    "Master password changed. Vault re-encrypted at {path}"
)