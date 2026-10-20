"""Security primitives: detection, encryption and authorisation."""

from __future__ import annotations

from .capability import CapabilityResult, CapabilityVerifier
from .crypto import (
    CryptoError,
    KeyVault,
    constant_time_equals,
    generate_key,
    hash_password,
    verify_password,
)
from .detector import (
    DetectionResult,
    analyse,
    analyse_fields,
    detect_sql_injection,
)

__all__ = [
    "CapabilityResult",
    "CapabilityVerifier",
    "CryptoError",
    "DetectionResult",
    "KeyVault",
    "analyse",
    "analyse_fields",
    "constant_time_equals",
    "detect_sql_injection",
    "generate_key",
    "hash_password",
    "verify_password",
]
