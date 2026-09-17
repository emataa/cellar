"""
Vault storage layer — bridges in-memory entries and an encrypted
JSON file on disk.

On-disk format: JSON envelope wrapping an AES-256-GCM-encrypted blob.
  {
    "version": 1,
    "kdf": {"name": "argon2id", "salt": <b64>, "time_cost": .., ...},
    "cipher": {"name": "aes-256-gcm", "nonce": <b64>, "ciphertext": <b64>}
  }
Decrypted plaintext is another JSON doc: {entry_name: {username, ...}}.

Writes are atomic + durable + concurrent-safe:
  - write to vault.json.tmp, fsync, os.replace onto vault.json,
    fsync the parent dir (survives a crash/power-loss mid-write)
  - advisory flock on a sidecar .lock file so two `pv` processes
    can't race and clobber each other's save

UnlockedVault is a context manager — use
`with UnlockedVault.unlock(...) as v:` so the key/plaintext get
dropped at block exit.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, UTC
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from cellar.constants import (
    ARGON2_MEMORY_KIB_PER_LANE_MIN,
    ARGON2_PARALLELISM_MIN,
    ARGON2_TIME_COST_MIN,
    CIPHER_KEY_CIPHERTEXT,
    CIPHER_KEY_NAME,
    CIPHER_KEY_NONCE,
    CIPHER_NAME_AES_256_GCM,
    KDF_KEY_MEMORY_COST,
    KDF_KEY_NAME,
    KDF_KEY_PARALLELISM,
    KDF_KEY_SALT,
    KDF_KEY_TIME_COST,
    KDF_NAME_ARGON2ID,
    KEY_LENGTH_BYTES,
    VAULT_FILE_MODE,
    VAULT_FORMAT_VERSION,
    VAULT_KEY_CIPHER,
    VAULT_KEY_KDF,
    VAULT_KEY_VERSION,
)
from cellar.crypto import (
    KdfParameters,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
)

# fcntl is POSIX-only. On Windows we skip advisory locking during
# save — os.replace is still atomic, we just lose cross-process
# serialization.
try:
    import fcntl as _fcntl
except ImportError:  # pragma: no cover — Windows
    _fcntl = None  # type: ignore[assignment]


# =============================================================================
# Exceptions
# =============================================================================


class VaultError(Exception):
    """Base class for vault errors."""


class VaultNotFoundError(VaultError):
    """No vault file at the given path."""


class VaultAlreadyExistsError(VaultError):
    """init() called on a path that already has a vault."""


class VaultFormatError(VaultError):
    """Vault file is unreadable or has unexpected fields."""


class EntryNotFoundError(VaultError):
    """Lookup by name with no matching entry."""


class EntryAlreadyExistsError(VaultError):
    """Add called with a name that already exists."""


# =============================================================================
# Helpers
# =============================================================================


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as exc:
        raise VaultFormatError(f"Invalid base64 in vault: {exc}") from exc


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _validate_entry_name(name: str) -> None:
    """
    Rejects empty/whitespace-only names and names with leading or
    trailing whitespace (otherwise "github" and "github " would
    silently become two different keys).
    """
    if not name or not name.strip():
        raise ValueError("Entry name cannot be empty or whitespace")
    if name != name.strip():
        raise ValueError("Entry name must not have leading or trailing whitespace")


@contextlib.contextmanager
def _file_lock(target_path: Path) -> Iterator[None]:
    """
    Advisory exclusive lock on a sidecar `.lock` file, held for the
    whole encrypt-and-write window so two `pv` processes can't race
    on the same vault. No-op on Windows (fcntl unavailable).
    """
    if _fcntl is None:  # pragma: no cover — Windows path
        yield
        return

    lock_path = target_path.with_suffix(target_path.suffix + ".lock")
    target_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, VAULT_FILE_MODE)
    try:
        _fcntl.flock(fd, _fcntl.LOCK_EX)
        try:
            yield
        finally:
            _fcntl.flock(fd, _fcntl.LOCK_UN)
    finally:
        os.close(fd)


# =============================================================================
# Entry
# =============================================================================


@dataclass(slots=True, frozen=True)
class Entry:
    """
    A single credential record. Frozen — the only way to "edit" one
    is through UnlockedVault.add_entry, which knows how to bump
    updated_at correctly.
    """

    username: str
    password: str
    url: str = ""
    notes: str = ""
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Entry:
        """
        Rebuild an Entry from a JSON-loaded dict. A missing
        username/password means the file is corrupted — we refuse
        the whole load rather than silently inventing an empty value.
        """
        try:
            username = data["username"]
            password = data["password"]
        except KeyError as exc:
            raise VaultFormatError(f"Entry missing required field: {exc}") from exc
        if not isinstance(username, str) or not isinstance(password, str):
            raise VaultFormatError("Entry username and password must be strings")
        return cls(
            username=username,
            password=password,
            url=data.get("url", ""),
            notes=data.get("notes", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


# =============================================================================
# UnlockedVault
# =============================================================================


@dataclass(slots=True)
class UnlockedVault:
    """
    An opened vault: entries + the crypto context needed to persist
    changes. Holds the derived key in memory for the session instead
    of re-running Argon2 on every save.
    """

    path: Path
    salt: bytes
    kdf_parameters: KdfParameters
    key: bytes
    entries: dict[str, Entry]

    # -------------------------------------------------------------------
    # Constructors
    # -------------------------------------------------------------------

    @classmethod
    def create(
        cls,
        path: Path,
        master_password: str,
        *,
        kdf_parameters: KdfParameters | None = None,
    ) -> Self:
        """
        Create a new empty vault and write it to disk. Refuses to
        overwrite an existing file. `kdf_parameters` lets tests pass
        weaker params so Argon2 finishes fast instead of hitting
        production defaults.
        """
        if path.exists():
            raise VaultAlreadyExistsError(f"Vault already exists at {path}")

        salt = generate_salt()
        kdf_parameters = kdf_parameters or KdfParameters.defaults()
        key = derive_key(master_password, salt, kdf_parameters)

        vault = cls(
            path=path,
            salt=salt,
            kdf_parameters=kdf_parameters,
            key=key,
            entries={},
        )
        vault.save()
        return vault

    @classmethod
    def unlock(cls, path: Path, master_password: str) -> Self:
        """Open an existing vault, deriving the key from the stored salt."""
        if not path.exists():
            raise VaultNotFoundError(f"No vault at {path}")

        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultFormatError(f"Vault file at {path} is not valid JSON: {exc}") from exc

        salt, kdf_parameters, nonce, ciphertext = _parse_envelope(envelope)

        # Use the params that were ACTUALLY used at encryption time,
        # not today's defaults — this is what keeps old vaults working.
        key = derive_key(master_password, salt, kdf_parameters)
        plaintext_bytes = decrypt(ciphertext, nonce, key)

        try:
            entries_data = json.loads(plaintext_bytes.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise VaultFormatError(f"Decrypted plaintext is not valid JSON: {exc}") from exc

        entries = {name: Entry.from_dict(row) for name, row in entries_data.items()}

        return cls(
            path=path,
            salt=salt,
            kdf_parameters=kdf_parameters,
            key=key,
            entries=entries,
        )

    # -------------------------------------------------------------------
    # Persistence
    # -------------------------------------------------------------------

    def save(self) -> None:
        """Encrypt entries and write atomically/durably, under a file lock."""
        entries_json = json.dumps(
            {name: entry.to_dict() for name, entry in self.entries.items()},
            sort_keys=True,
            indent=2,
        ).encode("utf-8")

        nonce, ciphertext = encrypt(entries_json, self.key)

        envelope = _build_envelope(
            salt=self.salt,
            kdf_parameters=self.kdf_parameters,
            nonce=nonce,
            ciphertext=ciphertext,
        )
        envelope_bytes = json.dumps(envelope, indent=2).encode("utf-8")

        self.path.parent.mkdir(parents=True, exist_ok=True)

        with _file_lock(self.path):
            self._atomic_write(envelope_bytes)

    def _atomic_write(self, envelope_bytes: bytes) -> None:
        """Write to a .tmp file, fsync, then atomically replace the real path."""
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")

        # os.open + os.write instead of Path.write_bytes so the file
        # is created at mode 0600 from the first syscall — write_bytes
        # would use the umask (often 0644) and need a separate chmod,
        # leaving a race window.
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, VAULT_FILE_MODE)
        try:
            try:
                os.write(fd, envelope_bytes)
                os.fsync(fd)
            finally:
                os.close(fd)

            os.replace(tmp_path, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(tmp_path)
            raise

        # fsync the parent dir so the rename survives a crash. NTFS
        # doesn't need this (no dir fsync on Windows).
        if os.name != "nt":
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    # -------------------------------------------------------------------
    # Entry operations
    # -------------------------------------------------------------------

    def names(self) -> list[str]:
        return sorted(self.entries.keys())

    def get_entry(self, name: str) -> Entry:
        try:
            return self.entries[name]
        except KeyError as exc:
            raise EntryNotFoundError(f"No entry named: {name}") from exc

    def add_entry(self, name: str, entry: Entry, *, force: bool = False) -> None:
        """Add or replace an entry. Refuses to overwrite unless force=True."""
        _validate_entry_name(name)
        if name in self.entries and not force:
            raise EntryAlreadyExistsError(f"Entry already exists: {name}")
        if name in self.entries:
            old = self.entries[name]
            entry = replace(entry, created_at=old.created_at, updated_at=_now_iso())
        self.entries[name] = entry

    def delete_entry(self, name: str) -> Entry:
        try:
            return self.entries.pop(name)
        except KeyError as exc:
            raise EntryNotFoundError(f"No entry named: {name}") from exc

    # -------------------------------------------------------------------
    # Master password rotation
    # -------------------------------------------------------------------

    def change_master_password(
        self,
        new_master_password: str,
        *,
        kdf_parameters: KdfParameters | None = None,
    ) -> None:
        """
        Generate a fresh salt + key from the new password. Only
        mutates in-memory state — call save() after to persist the
        re-encrypted vault.
        """
        if not new_master_password:
            raise ValueError("new_master_password must not be empty")

        new_salt = generate_salt()
        new_kdf_parameters = kdf_parameters or KdfParameters.defaults()
        new_key = derive_key(new_master_password, new_salt, new_kdf_parameters)

        self.salt = new_salt
        self.kdf_parameters = new_kdf_parameters
        self.key = new_key

    # -------------------------------------------------------------------
    # Context manager
    # -------------------------------------------------------------------

    def close(self) -> None:
        """
        Best-effort cleanup: clears entries and zeros the key. Python
        bytes are immutable, so the original key bytes may linger
        until GC — true wipe-on-free would need bytearray + ctypes,
        skipped here deliberately.
        """
        self.entries = {}
        self.key = bytes(KEY_LENGTH_BYTES)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.close()


# =============================================================================
# Envelope build / parse
# =============================================================================


def _build_envelope(
    salt: bytes,
    kdf_parameters: KdfParameters,
    nonce: bytes,
    ciphertext: bytes,
) -> dict[str, Any]:
    return {
        VAULT_KEY_VERSION: VAULT_FORMAT_VERSION,
        VAULT_KEY_KDF: {
            KDF_KEY_NAME: KDF_NAME_ARGON2ID,
            KDF_KEY_SALT: _b64encode(salt),
            KDF_KEY_TIME_COST: kdf_parameters.time_cost,
            KDF_KEY_MEMORY_COST: kdf_parameters.memory_cost,
            KDF_KEY_PARALLELISM: kdf_parameters.parallelism,
        },
        VAULT_KEY_CIPHER: {
            CIPHER_KEY_NAME: CIPHER_NAME_AES_256_GCM,
            CIPHER_KEY_NONCE: _b64encode(nonce),
            CIPHER_KEY_CIPHERTEXT: _b64encode(ciphertext),
        },
    }


def _parse_envelope(
    envelope: dict[str, Any],
) -> tuple[bytes, KdfParameters, bytes, bytes]:
    """Extract and validate (salt, kdf_parameters, nonce, ciphertext)."""
    if not isinstance(envelope, dict):
        raise VaultFormatError("Vault envelope is not a JSON object")

    version = envelope.get(VAULT_KEY_VERSION)
    if version != VAULT_FORMAT_VERSION:
        raise VaultFormatError(
            f"Unsupported vault version: {version} "
            f"(this build supports version {VAULT_FORMAT_VERSION})"
        )

    kdf = envelope.get(VAULT_KEY_KDF)
    cipher = envelope.get(VAULT_KEY_CIPHER)
    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise VaultFormatError("Vault envelope missing kdf or cipher section")

    if kdf.get(KDF_KEY_NAME) != KDF_NAME_ARGON2ID:
        raise VaultFormatError(f"Unsupported KDF: {kdf.get(KDF_KEY_NAME)}")
    try:
        salt = _b64decode(kdf[KDF_KEY_SALT])
        kdf_parameters = KdfParameters(
            time_cost=int(kdf[KDF_KEY_TIME_COST]),
            memory_cost=int(kdf[KDF_KEY_MEMORY_COST]),
            parallelism=int(kdf[KDF_KEY_PARALLELISM]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VaultFormatError(f"Invalid KDF section: {exc}") from exc

    # Sanity-check against Argon2's algorithmic minimums so a
    # corrupted/hand-edited file fails cleanly here instead of
    # crashing inside argon2-cffi with a confusing error.
    if kdf_parameters.time_cost < ARGON2_TIME_COST_MIN:
        raise VaultFormatError(
            f"Invalid Argon2 time_cost: "
            f"{kdf_parameters.time_cost} (minimum {ARGON2_TIME_COST_MIN})"
        )
    if kdf_parameters.parallelism < ARGON2_PARALLELISM_MIN:
        raise VaultFormatError(
            f"Invalid Argon2 parallelism: "
            f"{kdf_parameters.parallelism} (minimum {ARGON2_PARALLELISM_MIN})"
        )
    memory_floor = ARGON2_MEMORY_KIB_PER_LANE_MIN * kdf_parameters.parallelism
    if kdf_parameters.memory_cost < memory_floor:
        raise VaultFormatError(
            f"Invalid Argon2 memory_cost: "
            f"{kdf_parameters.memory_cost} KiB "
            f"(minimum {memory_floor} KiB for parallelism={kdf_parameters.parallelism})"
        )

    if cipher.get(CIPHER_KEY_NAME) != CIPHER_NAME_AES_256_GCM:
        raise VaultFormatError(f"Unsupported cipher: {cipher.get(CIPHER_KEY_NAME)}")
    try:
        nonce = _b64decode(cipher[CIPHER_KEY_NONCE])
        ciphertext = _b64decode(cipher[CIPHER_KEY_CIPHERTEXT])
    except KeyError as exc:
        raise VaultFormatError(f"Cipher section missing field: {exc}") from exc

    return salt, kdf_parameters, nonce, ciphertext