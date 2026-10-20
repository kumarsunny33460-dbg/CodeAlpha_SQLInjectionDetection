"""Registration service.

The service owns the security pipeline so that the HTTP layer stays thin and
the pipeline can be exercised directly from tests:

1. validate the payload
2. scan every field for SQL injection attempts
3. verify the capability code
4. encrypt the sensitive fields and hash the password
5. persist the record and log the security events
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from pymongo.errors import DuplicateKeyError

from ..db.repositories import (
    EVENT_SQL_INJECTION,
    EVENT_UNAUTHORIZED_ACCESS,
    EVENT_VALIDATION_ERROR,
    EventRepository,
    SecurityEvent,
    UserRepository,
)
from ..logging_config import get_logger
from ..schemas import validate_registration
from ..security.capability import CapabilityVerifier
from ..security.crypto import KeyVault, hash_password
from ..security.detector import analyse_fields

logger = get_logger("registration")


@dataclass
class RegistrationOutcome:
    """Result of a registration attempt."""

    success: bool
    message: str
    type: str = "success"
    status: int = 200
    field: str = ""
    score: int = 0
    detection: dict[str, Any] | None = None
    details: dict[str, Any] = dc_field(default_factory=dict)


class RegistrationService:
    """Runs the multi layer registration pipeline."""

    def __init__(
        self,
        user_repository: UserRepository,
        event_repository: EventRepository,
        key_vault: KeyVault,
        capability_verifier: CapabilityVerifier,
        config,
    ) -> None:
        self.users = user_repository
        self.events = event_repository
        self.vault = key_vault
        self.capability = capability_verifier
        self.config = config

    # -----------------------------------------------------------------
    # Pipeline
    # -----------------------------------------------------------------
    def register(
        self,
        payload: dict,
        context: dict[str, str] | None = None,
    ) -> RegistrationOutcome:
        context = context or {}

        # ---------------------------------------------------------
        # STEP 1 - SQL injection detection
        #
        # The scan runs before the format validation so that an
        # attack is always recorded as an attack, even when the
        # payload would also fail the field format rules.
        # ---------------------------------------------------------
        detection = analyse_fields(
            {
                "name": str(payload.get("name", "") or ""),
                "email": str(payload.get("email", "") or ""),
                "password": str(payload.get("password", "") or ""),
                "capability_code": str(payload.get("capability_code", "") or ""),
            },
            threshold=self.config.get("SQLI_BLOCK_THRESHOLD", 40),
        )

        if detection.is_injection:
            self._log_event(
                EVENT_SQL_INJECTION,
                source="Registration Form",
                context=context,
                payload=detection.evidence,
                category=(detection.categories[0] if detection.categories else "Unknown"),
                severity=detection.severity,
                score=detection.score,
                details={
                    "field": detection.field,
                    "matched_rules": list(detection.matched_rules),
                    "signals": list(detection.signals),
                },
            )

            logger.warning(
                "SQL injection attempt blocked",
                extra={
                    "context": {
                        "field": detection.field,
                        "score": detection.score,
                        "rules": list(detection.matched_rules),
                    }
                },
            )

            return RegistrationOutcome(
                success=False,
                message="SQL Injection Attack Detected. Request Blocked.",
                type="danger",
                status=403,
                field=detection.field,
                score=detection.score,
                detection=detection.to_dict(),
            )

        # ---------------------------------------------------------
        # STEP 2 - field validation
        # ---------------------------------------------------------
        validation = validate_registration(payload)
        if not validation.is_valid:
            self._log_event(
                EVENT_VALIDATION_ERROR,
                source="Registration Form",
                context=context,
                details={"fields": sorted(validation.errors)},
            )

            return RegistrationOutcome(
                success=False,
                message=validation.first_error(),
                type="warning",
                status=400,
                details={"errors": validation.errors},
            )

        values = validation.values

        # ---------------------------------------------------------
        # STEP 3 - capability code verification
        # ---------------------------------------------------------
        capability_result = self.capability.verify(
            values["capability_code"],
            client_id=context.get("ip_address", "global"),
        )

        if not capability_result.valid:
            self._log_event(
                EVENT_UNAUTHORIZED_ACCESS,
                source="Registration Form",
                context=context,
                payload="Invalid capability code",
                category=(
                    "Locked Out"
                    if capability_result.locked
                    else "Invalid Capability Code"
                ),
                severity="high" if capability_result.locked else "medium",
                details={
                    "reason": capability_result.reason,
                    "remaining_attempts": capability_result.remaining_attempts,
                },
            )

            if capability_result.locked:
                message = "Too many failed attempts. Access temporarily denied."
            elif not self.capability.is_configured:
                message = "Capability verification is not configured."
            else:
                message = "Invalid Capability Code. Access Denied."

            return RegistrationOutcome(
                success=False,
                message=message,
                type="warning",
                status=403,
                details={
                    "reason": capability_result.reason,
                    "remaining_attempts": capability_result.remaining_attempts,
                },
            )

        # ---------------------------------------------------------
        # STEP 4 - encryption and password hashing
        # ---------------------------------------------------------
        encrypted_name = self.vault.encrypt(values["name"], aad=b"name")
        encrypted_email = self.vault.encrypt(values["email"], aad=b"email")
        password_hash = hash_password(
            values["password"],
            iterations=self.config.get("PBKDF2_ITERATIONS", 600_000),
        )

        # ---------------------------------------------------------
        # STEP 5 - persist the secure record
        # ---------------------------------------------------------
        try:
            record_id = self.users.create(
                name=encrypted_name,
                email=encrypted_email,
                password_hash=password_hash,
                email_plain=values["email"],
                extra={
                    "capability_verified": True,
                    "request_id": context.get("request_id", ""),
                },
            )
        except DuplicateKeyError:
            self._log_event(
                EVENT_VALIDATION_ERROR,
                source="Registration Form",
                context=context,
                category="Duplicate Registration",
                details={"email": values["email"]},
            )

            return RegistrationOutcome(
                success=False,
                message="A record already exists for this email address.",
                type="warning",
                status=409,
            )

        logger.info(
            "Secure record created",
            extra={"context": {"record_id": record_id}},
        )

        return RegistrationOutcome(
            success=True,
            message="User data stored securely with AES-256 encryption.",
            type="success",
            status=201,
            details={"record_id": record_id},
        )

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def _log_event(
        self,
        event_type: str,
        source: str,
        context: dict[str, str] | None = None,
        payload: str = "",
        category: str = "",
        severity: str = "",
        score: int = 0,
        details: dict[str, Any] | None = None,
    ) -> None:
        context = context or {}

        try:
            self.events.record(
                SecurityEvent(
                    event_type=event_type,
                    source=source,
                    payload=payload,
                    category=category,
                    severity=severity,
                    score=score,
                    ip_address=context.get("ip_address", ""),
                    user_agent=context.get("user_agent", ""),
                    request_id=context.get("request_id", ""),
                    details=details or {},
                )
            )
        except Exception as error:  # noqa: BLE001 - logging must never break a request
            logger.warning(
                "Unable to persist the security event",
                extra={"context": {"error": str(error)}},
            )


__all__ = ["RegistrationOutcome", "RegistrationService"]
