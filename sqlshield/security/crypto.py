"""Cryptographic services: authenticated encryption and password hashing.

Two primitives are provided.

``KeyVault``
    AES-256-GCM encryption with support for multiple active keys so that a
    key can be rotated without downtime. Ciphertexts are stored in a versioned
    envelope (``enc:<key-id>:<base64>``) and may optionally be bound to a
    context string through the GCM additional authenticated data, which stops a
    ciphertext being replayed into a different field.

``hash_password`` / ``verify_password``
    PBKDF2-HMAC-SHA256 password hashing. Passwords are never stored in a
    recoverable form: they are salted and stretched, and verification is done
    with a constant time comparison.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..config import config_value

KEY_SIZE_BYTES = 32
NONCE_SIZE_BYTES = 12
SALT_SIZE_BYTES = 16
ENVELOPE_PREFIX = "enc"
DEFAULT_KEY_ID = "v1"
DEFAULT_PBKDF2_ITERATIONS = 600_000
PBKDF2_ALGORITHM = "sha256"


class CryptoError(RuntimeError):
    """Raised when cryptographic material is missing or malformed."""


def generate_key() -> str:
    """Return a new URL safe base64 encoded 256 bit key."""
    return base64.urlsafe_b64encode(os.urandom(KEY_SIZE_BYTES)).decode("utf-8")


def decode_key(raw: str) -> bytes:
    """Decode a base64 encoded key and validate its length."""
    try:
        decoded = base64.urlsafe_b64decode(raw)
    except Exception as error:  # noqa: BLE001 - surfaced as a configuration error
        raise CryptoError("AES key is not valid Base64.") from error

    if len(decoded) != KEY_SIZE_BYTES:
        raise CryptoError("AES key must decode to exactly 32 bytes for AES-256.")

    return decoded


@dataclass
class KeyVault:
    """Holds the encryption keys used by the application."""

    keys: dict[str, bytes] = field(default_factory=dict)
    active_key_id: str = DEFAULT_KEY_ID

    # -----------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------
    @classmethod
    def from_config(cls, config) -> KeyVault:
        """Build a vault from a Flask configuration object."""
        keys: dict[str, bytes] = {}

        for entry in config_value(config, "AES_KEYS", []) or []:
            if ":" not in entry:
                raise CryptoError(
                    "AES_KEYS entries must use the '<key-id>:<base64>' format."
                )
            key_id, _, raw = entry.partition(":")
            key_id = key_id.strip()
            if not key_id:
                raise CryptoError("AES_KEYS entries require a non empty key id.")
            keys[key_id] = decode_key(raw.strip())

        legacy_key = config_value(config, "AES_KEY", "") or ""
        if legacy_key and DEFAULT_KEY_ID not in keys:
            keys[DEFAULT_KEY_ID] = decode_key(legacy_key)

        active = config_value(config, "ACTIVE_KEY_ID", DEFAULT_KEY_ID) or DEFAULT_KEY_ID
        if keys and active not in keys:
            active = next(iter(keys))

        return cls(keys=keys, active_key_id=active)

    # -----------------------------------------------------------------
    # Introspection
    # -----------------------------------------------------------------
    @property
    def is_ready(self) -> bool:
        return bool(self.keys)

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(self.keys)

    def require_keys(self) -> None:
        if not self.keys:
            raise CryptoError(
                "No AES key configured. Set AES_KEYS (or AES_KEY) in the environment."
            )

    # -----------------------------------------------------------------
    # Encryption
    # -----------------------------------------------------------------
    def encrypt(
        self,
        plaintext: str,
        aad: bytes | None = None,
        key_id: str | None = None,
    ) -> str:
        """Encrypt ``plaintext`` and return the versioned envelope."""
        self.require_keys()

        target = key_id or self.active_key_id
        if target not in self.keys:
            raise CryptoError(f"Unknown encryption key id '{target}'.")

        key = self.keys[target]
        nonce = os.urandom(NONCE_SIZE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, str(plaintext).encode("utf-8"), aad)

        payload = base64.urlsafe_b64encode(nonce + ciphertext).decode("utf-8")
        return f"{ENVELOPE_PREFIX}:{target}:{payload}"

    def decrypt(self, token: str, aad: bytes | None = None) -> str:
        """Decrypt an envelope produced by :meth:`encrypt`."""
        self.require_keys()

        if not token:
            raise CryptoError("Cannot decrypt an empty value.")

        key_ids = list(self.keys)
        payload = token

        if token.startswith(f"{ENVELOPE_PREFIX}:"):
            _, _, remainder = token.partition(":")
            key_id, _, payload = remainder.partition(":")
            if key_id not in self.keys:
                raise CryptoError(f"Unknown encryption key id '{key_id}'.")
            key_ids = [key_id]

        try:
            raw = base64.urlsafe_b64decode(payload)
        except Exception as error:  # noqa: BLE001
            raise CryptoError("Encrypted payload is not valid Base64.") from error

        if len(raw) <= NONCE_SIZE_BYTES:
            raise CryptoError("Encrypted payload is truncated.")

        nonce, ciphertext = raw[:NONCE_SIZE_BYTES], raw[NONCE_SIZE_BYTES:]

        for candidate in key_ids:
            try:
                plaintext = AESGCM(self.keys[candidate]).decrypt(nonce, ciphertext, aad)
                return plaintext.decode("utf-8")
            except Exception:  # noqa: BLE001, S112 - the next key may still work
                continue

        raise CryptoError("Unable to decrypt the payload with any known key.")

    def reencrypt(self, token: str, aad: bytes | None = None) -> str:
        """Re-encrypt ``token`` with the currently active key."""
        return self.encrypt(self.decrypt(token, aad=aad), aad=aad)


# ---------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------


def hash_password(
    password: str,
    iterations: int = DEFAULT_PBKDF2_ITERATIONS,
    salt: bytes | None = None,
) -> str:
    """Hash ``password`` using PBKDF2-HMAC-SHA256.

    The returned string encodes the algorithm, the work factor, the salt and
    the derived key so that the work factor can be raised later without
    invalidating existing records.
    """
    if password is None:
        raise CryptoError("Password cannot be None.")

    if salt is None:
        salt = os.urandom(SALT_SIZE_BYTES)

    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        str(password).encode("utf-8"),
        salt,
        iterations,
    )

    return "$".join(
        [
            f"pbkdf2_{PBKDF2_ALGORITHM}",
            str(iterations),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(derived).decode("ascii"),
        ]
    )


def verify_password(password: str, stored: str) -> bool:
    """Verify ``password`` against a hash produced by :func:`hash_password`."""
    if not password or not stored:
        return False

    parts = stored.split("$")
    if len(parts) != 4:
        return False

    algorithm, iterations_raw, salt_raw, hash_raw = parts

    if algorithm != f"pbkdf2_{PBKDF2_ALGORITHM}":
        return False

    try:
        iterations = int(iterations_raw)
        salt = base64.urlsafe_b64decode(salt_raw)
        expected = base64.urlsafe_b64decode(hash_raw)
    except (ValueError, TypeError):
        return False

    if iterations <= 0:
        return False

    derived = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        str(password).encode("utf-8"),
        salt,
        iterations,
    )

    return hmac.compare_digest(derived, expected)


def constant_time_equals(left: str, right: str) -> bool:
    """Compare two secrets without leaking their contents through timing."""
    if left is None or right is None:
        return False
    return hmac.compare_digest(str(left).encode("utf-8"), str(right).encode("utf-8"))


def random_token(length: int = 32) -> str:
    """Return a URL safe random token."""
    return secrets.token_urlsafe(length)


__all__ = [
    "CryptoError",
    "KeyVault",
    "constant_time_equals",
    "decode_key",
    "generate_key",
    "hash_password",
    "random_token",
    "verify_password",
]
