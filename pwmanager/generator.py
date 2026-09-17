"""
Cryptographically secure password generator. Uses `secrets`, not
`random` — `random` is predictable enough that seeing one output can
let an attacker reconstruct the generator state.
"""

import secrets

from pwmanager.constants import (
    DEFAULT_GENERATED_PASSWORD_LENGTH,
    DIGITS,
    LOWERCASE_LETTERS,
    MINIMUM_GENERATED_PASSWORD_LENGTH,
    SAFE_SYMBOLS,
    UPPERCASE_LETTERS,
)


class PasswordTooShortError(ValueError):
    """Requested length is below the safe minimum."""


def generate_password(
    length: int = DEFAULT_GENERATED_PASSWORD_LENGTH,
    *,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a random password of `length` characters. Guarantees at
    least one char from each enabled pool, then fills the rest and
    shuffles — otherwise a random draw could land all-lowercase and
    fail "must contain a digit" checks despite being genuinely random.
    """
    if length < MINIMUM_GENERATED_PASSWORD_LENGTH:
        raise PasswordTooShortError(
            f"Password length must be >= "
            f"{MINIMUM_GENERATED_PASSWORD_LENGTH}, got {length}"
        )

    enabled_pools = {
        "lower": LOWERCASE_LETTERS if use_lowercase else "",
        "upper": UPPERCASE_LETTERS if use_uppercase else "",
        "digit": DIGITS if use_digits else "",
        "symbol": SAFE_SYMBOLS if use_symbols else "",
    }
    enabled_pools = {k: v for k, v in enabled_pools.items() if v}

    if not enabled_pools:
        raise ValueError("At least one character pool must be enabled")

    if length < len(enabled_pools):
        raise PasswordTooShortError(
            f"length={length} is too small to include one character "
            f"from each of {len(enabled_pools)} enabled pools"
        )

    alphabet = "".join(enabled_pools.values())

    # One guaranteed char per pool, then fill the rest from the combined set
    required = [secrets.choice(pool) for pool in enabled_pools.values()]
    fill_count = length - len(required)
    fill = [secrets.choice(alphabet) for _ in range(fill_count)]

    chars = required + fill
    _secure_shuffle(chars)

    return "".join(chars)


def _secure_shuffle(items: list[str]) -> None:
    """
    Fisher-Yates shuffle using `secrets` instead of the predictable
    Mersenne Twister behind random.shuffle. Mutates in place.
    """
    for i in range(len(items) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        items[i], items[j] = items[j], items[i]