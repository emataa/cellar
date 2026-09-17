"""
Package init — re-exports public API so callers can do
`from pwmanager import UnlockedVault` instead of reaching into
pwmanager.vault directly.
"""

from pwmanager.crypto import (
    CryptoError,
    KdfParameters,
    WrongPasswordError,
)
from pwmanager.vault import (
    Entry,
    EntryAlreadyExistsError,
    EntryNotFoundError,
    UnlockedVault,
    VaultAlreadyExistsError,
    VaultError,
    VaultFormatError,
    VaultNotFoundError,
)


__version__ = "1.0.0"

__all__ = [
    "CryptoError",
    "Entry",
    "EntryAlreadyExistsError",
    "EntryNotFoundError",
    "KdfParameters",
    "UnlockedVault",
    "VaultAlreadyExistsError",
    "VaultError",
    "VaultFormatError",
    "VaultNotFoundError",
    "WrongPasswordError",
]