"""Compatibility shim for the original ``encryption`` module.

The cryptographic implementation now lives in :mod:`sqlshield.security.crypto`.
``encrypt_data`` keeps its original signature: it accepts a plaintext string
and returns a base64 encoded, authenticated ciphertext.
"""

from __future__ import annotations

from dotenv import load_dotenv

from sqlshield.config import resolve_config
from sqlshield.security.crypto import (
    CryptoError,
    KeyVault,
    constant_time_equals,
    generate_key,
    hash_password,
    verify_password,
)

load_dotenv()

_config = resolve_config()

_vault: KeyVault | None = None


def get_vault() -> KeyVault:
    """Return the process wide key vault."""
    global _vault

    if _vault is None:
        _vault = KeyVault.from_config(_config)

    return _vault


def get_aes_key() -> bytes:
    """Return the active encryption key as raw bytes."""
    vault = get_vault()
    vault.require_keys()
    return vault.keys[vault.active_key_id]


def encrypt_data(data) -> str:
    """Encrypt ``data`` and return the base64 envelope."""
    return get_vault().encrypt(data)


def decrypt_data(token) -> str:
    """Decrypt a value produced by :func:`encrypt_data`."""
    return get_vault().decrypt(token)


__all__ = [
    "CryptoError",
    "constant_time_equals",
    "decrypt_data",
    "encrypt_data",
    "generate_key",
    "get_aes_key",
    "get_vault",
    "hash_password",
    "verify_password",
]
