"""Tests for the SQL injection detection engine."""

from __future__ import annotations

import pytest

from sqlshield.security.detector import (
    analyse,
    analyse_fields,
    detect_sql_injection,
    normalize,
)


class TestTruePositives:
    """Payloads that must always be blocked."""

    @pytest.mark.parametrize(
        "payload",
        [
            "' OR '1'='1",
            "' OR 1=1 --",
            "admin' OR '1'='1",
            "1' UNION SELECT NULL, NULL --",
            "x' UNION ALL SELECT password FROM users --",
            "'; DROP TABLE users; --",
            "1; DELETE FROM SecureUsers",
            "1' AND SLEEP(5) --",
            "1' OR BENCHMARK(1000000,MD5(1)) --",
            "1' WAITFOR DELAY '0:0:5' --",
            "' OR 1=1 #",
            "') OR ('1'='1",
            "1' AND ASCII(SUBSTRING((SELECT name FROM users),1,1)) > 77 --",
            "1' UNION SELECT table_name FROM information_schema.tables --",
            "1'; EXEC xp_cmdshell('dir') --",
            "Robert'); DROP TABLE Students;--",
        ],
    )
    def test_payload_is_detected(self, payload):
        result = analyse(payload, field_name="name")
        assert result.is_injection is True
        assert result.score >= 40
        assert result.severity != "none"

    def test_union_select_is_critical(self):
        result = analyse("1 UNION SELECT password FROM users", field_name="name")
        assert result.severity == "critical"
        assert "union_select" in result.matched_rules

    def test_stacked_query_is_critical(self):
        result = analyse("value; DROP TABLE users", field_name="name")
        assert "stacked_query" in result.matched_rules
        assert result.score >= 90


class TestFalsePositives:
    """Legitimate input that must never be blocked."""

    @pytest.mark.parametrize(
        "payload",
        [
            "Sunny Kumar",
            "Anne-Marie O'Brien",
            "D'Angelo Rossi",
            "Michael Jordan",
            "sunny.kumar+work@example.co.uk",
            "normal text with a # character",
            "price range 10 - 20",
            "C# developer",
            "Hello, World!",
        ],
    )
    def test_legitimate_input_is_allowed(self, payload):
        result = analyse(payload, field_name="name")
        assert result.is_injection is False

    def test_password_may_contain_comment_markers(self):
        result = analyse("my-pass#word--x", field_name="password")
        assert result.is_injection is False

    def test_capability_code_is_not_inspected_for_comments(self):
        result = analyse("abc#def--ghi", field_name="capability_code")
        assert result.is_injection is False

    def test_empty_value_is_allowed(self):
        result = analyse("", field_name="name")
        assert result.is_injection is False
        assert result.score == 0

    def test_none_value_is_allowed(self):
        assert analyse(None, field_name="name").is_injection is False


class TestObfuscation:
    """Evasion techniques that must be unwrapped before detection."""

    def test_url_encoded_payload_is_detected(self):
        result = analyse("%27%20OR%20%271%27%3D%271", field_name="name")
        assert result.is_injection is True
        assert "encoded_payload" in result.signals

    def test_double_url_encoded_payload_is_detected(self):
        result = analyse("%2527%2520OR%25201%253D1", field_name="name")
        assert result.is_injection is True

    def test_html_entity_payload_is_detected(self):
        result = analyse("&#39; OR 1=1 &#39;", field_name="name")
        assert result.is_injection is True

    def test_comment_separated_keywords_are_detected(self):
        result = analyse("1 UNI/**/ON SEL/**/ECT NULL", field_name="name")
        assert result.is_injection is True
        assert "union_select" in result.matched_rules

    def test_null_byte_is_detected(self):
        result = analyse("admin\x00' OR 1=1 --", field_name="name")
        assert result.is_injection is True
        assert "null_byte" in result.matched_rules

    def test_full_width_characters_are_normalised(self):
        prepared, _, _ = normalize("＇ OR 1=1 ＇")
        assert "or 1=1" in prepared


class TestDetectorContract:
    """Behaviour of the public helpers."""

    def test_detect_sql_injection_returns_boolean(self):
        assert detect_sql_injection("' OR 1=1 --") is True
        assert detect_sql_injection("Sunny Kumar") is False

    def test_threshold_is_respected(self):
        assert analyse("admin'--", field_name="name", threshold=0).is_injection
        assert not analyse("admin'--", field_name="name", threshold=100).is_injection

    def test_analyse_fields_returns_the_worst_field(self):
        result = analyse_fields(
            {"name": "Sunny", "email": "' OR 1=1 --", "password": "x"},
            threshold=40,
        )
        assert result.field == "email"
        assert result.is_injection is True

    def test_analyse_fields_accepts_benign_input(self):
        result = analyse_fields(
            {"name": "Sunny", "email": "a@b.com", "password": "x"},
            threshold=40,
        )
        assert result.is_injection is False

    def test_result_serialises_to_a_dictionary(self):
        payload = analyse("' OR 1=1 --", field_name="name").to_dict()
        assert payload["is_injection"] is True
        assert "matched_rules" in payload
        assert "severity" in payload

    def test_evidence_is_bounded(self):
        result = analyse("'" + "A" * 5000 + "' OR 1=1 --", field_name="name")
        assert len(result.evidence) <= 130
