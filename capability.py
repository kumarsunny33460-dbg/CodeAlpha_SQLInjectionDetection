"""Compatibility shim for the original ``capability`` module.

The verification logic now lives in :mod:`sqlshield.security.capability`.
``check_capability_code`` keeps its original boolean contract.
"""

from __future__ import annotations

from dotenv import load_dotenv

from sqlshield.config import resolve_config
from sqlshield.security.capability import CapabilityResult, CapabilityVerifier

load_dotenv()

_config = resolve_config()

_verifier: CapabilityVerifier | None = None


def get_verifier() -> CapabilityVerifier:
    """Return the process wide capability verifier."""
    global _verifier

    if _verifier is None:
        _verifier = CapabilityVerifier.from_config(_config)

    return _verifier


def check_capability_code(code) -> bool:
    """Return ``True`` when ``code`` is a valid capability code."""
    return get_verifier().verify(code).valid


def verify_capability_code(code, client_id: str = "global") -> CapabilityResult:
    """Return the full verification result for ``code``."""
    return get_verifier().verify(code, client_id=client_id)


__all__ = [
    "CapabilityResult",
    "check_capability_code",
    "get_verifier",
    "verify_capability_code",
]
