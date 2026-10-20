"""Capability code verification.

The capability code is the second authorisation layer of the application: a
request must present a valid code before any data is accepted.

Compared with the original implementation this module adds:

* constant time comparison, so an attacker cannot recover the code by
  measuring response times;
* support for several valid codes and for a SHA-256 digest of the code, so
  the plaintext secret does not have to be stored in the environment;
* a brute force tracker that locks a client out after repeated failures.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass, field

from ..config import config_value
from .crypto import constant_time_equals


@dataclass
class CapabilityResult:
    """Outcome of a capability code check."""

    valid: bool
    reason: str = ""
    locked: bool = False
    remaining_attempts: int = 0

    def __bool__(self) -> bool:
        return self.valid


@dataclass
class _AttemptState:
    failures: int = 0
    locked_until: float = 0.0
    history: list[float] = field(default_factory=list)


class CapabilityVerifier:
    """Verifies capability codes and tracks repeated failures."""

    def __init__(
        self,
        codes: list[str] | None = None,
        code_sha256: str = "",
        max_attempts: int = 5,
        lockout_seconds: int = 300,
    ) -> None:
        self.codes = [code.strip() for code in (codes or []) if code and code.strip()]
        self.code_sha256 = (code_sha256 or "").strip().lower()
        self.max_attempts = max(1, int(max_attempts))
        self.lockout_seconds = max(0, int(lockout_seconds))
        self._attempts: dict[str, _AttemptState] = {}
        self._lock = threading.Lock()

    # -----------------------------------------------------------------
    # Construction
    # -----------------------------------------------------------------
    @classmethod
    def from_config(cls, config) -> CapabilityVerifier:
        codes = list(config_value(config, "CAPABILITY_CODES", []) or [])
        legacy = config_value(config, "CAPABILITY_CODE", "") or ""
        if legacy and legacy not in codes:
            codes.append(legacy)

        return cls(
            codes=codes,
            code_sha256=config_value(config, "CAPABILITY_CODE_SHA256", "") or "",
            max_attempts=config_value(config, "CAPABILITY_MAX_ATTEMPTS", 5),
            lockout_seconds=config_value(config, "CAPABILITY_LOCKOUT_SECONDS", 300),
        )

    @property
    def is_configured(self) -> bool:
        return bool(self.codes) or bool(self.code_sha256)

    # -----------------------------------------------------------------
    # Verification
    # -----------------------------------------------------------------
    def verify(self, code: str, client_id: str = "global") -> CapabilityResult:
        """Verify ``code`` for ``client_id``."""
        if not self.is_configured:
            return CapabilityResult(valid=False, reason="not_configured")

        state = self._state(client_id)

        if state.locked_until > time.time():
            return CapabilityResult(
                valid=False,
                reason="locked",
                locked=True,
                remaining_attempts=0,
            )

        candidate = (code or "").strip()
        if not candidate:
            self._record_failure(client_id)
            return CapabilityResult(
                valid=False,
                reason="empty",
                remaining_attempts=self._remaining(client_id),
            )

        if self._matches(candidate):
            self._reset(client_id)
            return CapabilityResult(valid=True, reason="ok")

        self._record_failure(client_id)
        return CapabilityResult(
            valid=False,
            reason="mismatch",
            remaining_attempts=self._remaining(client_id),
        )

    def _matches(self, candidate: str) -> bool:
        for stored in self.codes:
            if constant_time_equals(candidate, stored):
                return True

        if self.code_sha256:
            digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
            if hmac.compare_digest(digest, self.code_sha256):
                return True

        return False

    # -----------------------------------------------------------------
    # Brute force tracking
    # -----------------------------------------------------------------
    def _state(self, client_id: str) -> _AttemptState:
        with self._lock:
            return self._attempts.setdefault(client_id or "global", _AttemptState())

    def _record_failure(self, client_id: str) -> None:
        with self._lock:
            state = self._attempts.setdefault(client_id or "global", _AttemptState())
            state.failures += 1
            state.history.append(time.time())
            if state.failures >= self.max_attempts and self.lockout_seconds > 0:
                state.locked_until = time.time() + self.lockout_seconds

    def _reset(self, client_id: str) -> None:
        with self._lock:
            state = self._attempts.setdefault(client_id or "global", _AttemptState())
            state.failures = 0
            state.locked_until = 0.0
            state.history.clear()

    def _remaining(self, client_id: str) -> int:
        with self._lock:
            state = self._attempts.get(client_id or "global")
            if state is None:
                return self.max_attempts
            return max(0, self.max_attempts - state.failures)

    def is_locked(self, client_id: str) -> bool:
        state = self._state(client_id)
        return state.locked_until > time.time()


__all__ = ["CapabilityResult", "CapabilityVerifier"]
