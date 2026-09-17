"""
Package init — re-exports public API so callers can do
`from cellar import UnlockedVault` instead of reaching into
cellar.vault directly.
"""

from cellar.crypto import (
    CryptoError,
    KdfParameters,
    WrongPasswordError,
)
from cellar.vault import (
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