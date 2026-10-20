"""Tests for the capability code verification."""

from __future__ import annotations

import hashlib

from sqlshield.security.capability import CapabilityVerifier


class TestVerification:
    def test_a_valid_code_is_accepted(self):
        verifier = CapabilityVerifier(codes=["let-me-in"])
        assert verifier.verify("let-me-in").valid is True

    def test_the_code_is_trimmed(self):
        verifier = CapabilityVerifier(codes=["let-me-in"])
        assert verifier.verify("  let-me-in  ").valid is True

    def test_an_invalid_code_is_rejected(self):
        verifier = CapabilityVerifier(codes=["let-me-in"])
        result = verifier.verify("nope")
        assert result.valid is False
        assert result.reason == "mismatch"

    def test_an_empty_code_is_rejected(self):
        verifier = CapabilityVerifier(codes=["let-me-in"])
        assert verifier.verify("").reason == "empty"

    def test_multiple_codes_are_supported(self):
        verifier = CapabilityVerifier(codes=["one", "two"])
        assert verifier.verify("one").valid is True
        assert verifier.verify("two").valid is True

    def test_a_sha256_digest_can_be_used(self):
        digest = hashlib.sha256(b"let-me-in").hexdigest()
        verifier = CapabilityVerifier(codes=[], code_sha256=digest)
        assert verifier.verify("let-me-in").valid is True
        assert verifier.verify("nope").valid is False

    def test_an_unconfigured_verifier_denies_everything(self):
        verifier = CapabilityVerifier()
        assert verifier.is_configured is False
        assert verifier.verify("anything").valid is False


class TestBruteForceProtection:
    def test_the_client_is_locked_after_the_limit(self):
        verifier = CapabilityVerifier(codes=["let-me-in"], max_attempts=3)

        for _ in range(3):
            verifier.verify("wrong", client_id="1.2.3.4")

        result = verifier.verify("let-me-in", client_id="1.2.3.4")
        assert result.valid is False
        assert result.locked is True
        assert result.reason == "locked"

    def test_a_success_resets_the_counter(self):
        verifier = CapabilityVerifier(codes=["let-me-in"], max_attempts=3)

        verifier.verify("wrong", client_id="1.2.3.4")
        verifier.verify("wrong", client_id="1.2.3.4")
        assert verifier.verify("let-me-in", client_id="1.2.3.4").valid is True

        assert verifier.verify("wrong", client_id="1.2.3.4").reason == "mismatch"

    def test_the_lockout_is_scoped_to_the_client(self):
        verifier = CapabilityVerifier(codes=["let-me-in"], max_attempts=2)

        for _ in range(2):
            verifier.verify("wrong", client_id="1.2.3.4")

        assert verifier.verify("let-me-in", client_id="5.6.7.8").valid is True

    def test_remaining_attempts_are_reported(self):
        verifier = CapabilityVerifier(codes=["let-me-in"], max_attempts=3)
        verifier.verify("wrong", client_id="1.2.3.4")
        assert verifier.verify("wrong", client_id="1.2.3.4").remaining_attempts == 1
