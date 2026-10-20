"""Request validation.

Validation is deliberately dependency free: the payload is small and the rules
are simple, so a dedicated schema library would add weight without adding
value. Each validator returns a list of human readable errors.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
NAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z\s.'-]*$")

MAX_NAME_LENGTH = 120
MIN_NAME_LENGTH = 2
MAX_EMAIL_LENGTH = 254
MAX_PASSWORD_LENGTH = 128
MIN_PASSWORD_LENGTH = 8
MAX_CAPABILITY_LENGTH = 256


@dataclass
class ValidationResult:
    """Outcome of validating a registration payload."""

    values: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def first_error(self) -> str:
        if not self.errors:
            return ""
        return next(iter(self.errors.values()))


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def validate_registration(payload: dict) -> ValidationResult:
    """Validate a registration payload."""
    result = ValidationResult()

    name = _as_text(payload.get("name"))
    email = _as_text(payload.get("email"))
    password = payload.get("password")
    password = "" if password is None else str(password)
    capability_code = _as_text(payload.get("capability_code"))

    if not name:
        result.errors["name"] = "Full name is required."
    elif len(name) < MIN_NAME_LENGTH:
        result.errors["name"] = (
            f"Full name must be at least {MIN_NAME_LENGTH} characters long."
        )
    elif len(name) > MAX_NAME_LENGTH:
        result.errors["name"] = f"Full name must not exceed {MAX_NAME_LENGTH} characters."
    elif not NAME_PATTERN.match(name):
        result.errors["name"] = (
            "Full name may only contain letters, spaces, apostrophes, "
            "hyphens and periods."
        )

    if not email:
        result.errors["email"] = "Email address is required."
    elif len(email) > MAX_EMAIL_LENGTH:
        result.errors["email"] = (
            f"Email address must not exceed {MAX_EMAIL_LENGTH} characters."
        )
    elif not EMAIL_PATTERN.match(email):
        result.errors["email"] = "A valid email address is required."

    if not password:
        result.errors["password"] = "Password is required."  # noqa: S105
    elif len(password) < MIN_PASSWORD_LENGTH:
        result.errors["password"] = (
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long."
        )
    elif len(password) > MAX_PASSWORD_LENGTH:
        result.errors["password"] = (
            f"Password must not exceed {MAX_PASSWORD_LENGTH} characters."
        )

    if not capability_code:
        result.errors["capability_code"] = "Capability code is required."
    elif len(capability_code) > MAX_CAPABILITY_LENGTH:
        result.errors["capability_code"] = (
            f"Capability code must not exceed {MAX_CAPABILITY_LENGTH} characters."
        )

    result.values = {
        "name": name,
        "email": email,
        "password": password,
        "capability_code": capability_code,
    }

    return result


__all__ = [
    "MAX_CAPABILITY_LENGTH",
    "MAX_EMAIL_LENGTH",
    "MAX_NAME_LENGTH",
    "MAX_PASSWORD_LENGTH",
    "MIN_NAME_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "ValidationResult",
    "validate_registration",
]
