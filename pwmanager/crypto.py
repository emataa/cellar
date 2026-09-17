"""
Crypto layer: Argon2id key derivation + AES-256-GCM encryption.

Master password -> derive_key() -> 32-byte key -> encrypt/decrypt
vault contents. Argon2id is deliberately slow/memory-hungry to make
brute-forcing the master password expensive. AES-GCM gives us
confidentiality + tamper detection in one primitive.
"""

import secrets
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pwmanager.constants import (
    ARGON2_MEMORY_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    KEY_LENGTH_BYTES,
    NONCE_LENGTH_BYTES,
    SALT_LENGTH_BYTES,
)


class CryptoError(Exception):
    """Base class for crypto errors."""


class WrongPasswordError(CryptoError):
    """
    Raised on decryption failure. Could mean wrong password, tampered
    file, or corruption — we can't distinguish, and don't try, since
    exposing the difference would help an attacker.
    """


@dataclass(frozen=True, slots=True)
class KdfParameters:
    """
    Argon2id tuning knobs, bundled so they can be stored alongside
    the ciphertext. This is what lets old vaults keep working if we
    bump the defaults later — each vault remembers its own params.
    """

    time_cost: int
    memory_cost: int
    parallelism: int

    @classmethod
    def defaults(cls) -> "KdfParameters":
        return cls(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
        )


def generate_salt() -> bytes:
    """Fresh random salt for a new vault. Not secret, just unique."""
    return secrets.token_bytes(SALT_LENGTH_BYTES)


def generate_nonce() -> bytes:
    """
    Fresh random nonce, generated per-encryption. Reusing a nonce
    with the same key under GCM leaks plaintext — never cache this.
    """
    return secrets.token_bytes(NONCE_LENGTH_BYTES)


def derive_key(
    master_password: str,
    salt: bytes,
    parameters: KdfParameters | None = None,
) -> bytes:
    """
    Derive a 32-byte AES key from a master password + salt via
    Argon2id. Same password + salt always yields the same key.
    Expect ~0.3-1s per call at default params — that cost is the
    point.
    """
    if not master_password:
        raise ValueError("master_password must not be empty")

    if parameters is None:
        parameters = KdfParameters.defaults()

    password_bytes = master_password.encode("utf-8")

    return hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=parameters.time_cost,
        memory_cost=parameters.memory_cost,
        parallelism=parameters.parallelism,
        hash_len=KEY_LENGTH_BYTES,
        type=Type.ID,  # Argon2id: resists both side-channel and GPU attacks
    )


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    AES-256-GCM encrypt. Returns (nonce, ciphertext_with_tag) — the
    caller must store both; the nonce is required for decryption.
    """
    cipher = AESGCM(key)
    nonce = generate_nonce()
    ciphertext = cipher.encrypt(nonce=nonce, data=plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    AES-256-GCM decrypt + verify. Raises WrongPasswordError if the
    auth tag doesn't validate (wrong key, wrong nonce, or tampering).
    """
    cipher = AESGCM(key)
    try:
        return cipher.decrypt(nonce=nonce, data=ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise WrongPasswordError(
            "Decryption failed: wrong master password or corrupted vault"
        ) from exc