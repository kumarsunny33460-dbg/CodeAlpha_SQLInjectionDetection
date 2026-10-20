"""Tests for the data access layer."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pymongo.errors import DuplicateKeyError

from sqlshield.db.repositories import (
    EVENT_SQL_INJECTION,
    EVENT_SYSTEM,
    EventRepository,
    SecurityEvent,
    UserRepository,
    format_timestamp,
)


@pytest.fixture()
def users(mongo_manager):
    return UserRepository(mongo_manager.users, fingerprint_key=b"test-key")


@pytest.fixture()
def events(mongo_manager):
    return EventRepository(mongo_manager.events)


@pytest.fixture()
def mongo_manager(app):
    return app.extensions["mongo"]


class TestUserRepository:
    def test_a_record_is_created(self, users):
        record_id = users.create("Sunny", "sunny@example.com", "hash")

        assert record_id
        assert users.count() == 1

    def test_the_email_is_fingerprinted_not_stored_in_clear(self, users, mongo_manager):
        users.create("Sunny", "sunny@example.com", "hash")

        document = mongo_manager.users.find_one({})
        assert "sunny@example.com" not in str(document["email_fingerprint"])
        assert document["email_fingerprint"]

    def test_the_fingerprint_is_stable(self, users):
        first = users.fingerprint("Sunny@Example.com")
        second = users.fingerprint("sunny@example.com")
        assert first == second

    def test_the_fingerprint_differs_for_other_addresses(self, users):
        assert users.fingerprint("a@example.com") != users.fingerprint("b@example.com")

    def test_existing_email_is_detected(self, users):
        users.create("Sunny", "sunny@example.com", "hash")
        assert users.exists("sunny@example.com") is True
        assert users.exists("other@example.com") is False

    def test_the_fingerprint_uses_the_clear_text_address(self, users, mongo_manager):
        users.create(
            "Sunny",
            "enc:v1:ciphertext",
            "hash",
            email_plain="sunny@example.com",
        )

        document = mongo_manager.users.find_one({})
        assert document["email_fingerprint"] == users.fingerprint("sunny@example.com")

    def test_two_encryptions_of_the_same_email_collide(self, users, mongo_manager):
        users.create("Sunny", "enc:v1:first", "hash", email_plain="a@b.com")

        with pytest.raises(DuplicateKeyError):
            users.create("Sunny", "enc:v1:second", "hash", email_plain="a@b.com")

        assert mongo_manager.users.count_documents({}) == 1

    def test_the_recent_listing_hides_the_sensitive_fields(self, users, mongo_manager):
        users.create("Sunny", "sunny@example.com", "hash")

        records = users.recent(limit=5)

        assert len(records) == 1
        assert records[0]["number"] == 1
        assert "email" not in records[0]
        assert "name" not in records[0]

    def test_the_created_at_field_is_formatted(self, users):
        users.create("Sunny", "sunny@example.com", "hash")
        assert users.recent(limit=1)[0]["created_at"] != "N/A"


class TestEventRepository:
    def test_an_event_is_recorded(self, events):
        event_id = events.record(
            SecurityEvent(
                event_type=EVENT_SQL_INJECTION,
                source="Registration Form",
                payload="' OR 1=1 --",
            )
        )

        assert event_id
        assert events.count() == 1

    def test_the_payload_is_truncated(self, events, mongo_manager):
        events.record(
            SecurityEvent(
                event_type=EVENT_SYSTEM,
                source="Test",
                payload="A" * 5000,
            )
        )

        document = mongo_manager.events.find_one({})
        assert len(document["payload"]) == 500

    def test_the_counts_are_grouped_by_type(self, events):
        events.record(SecurityEvent(event_type=EVENT_SQL_INJECTION, source="A"))
        events.record(SecurityEvent(event_type=EVENT_SQL_INJECTION, source="A"))
        events.record(SecurityEvent(event_type=EVENT_SYSTEM, source="B"))

        counts = events.counts_by_type()

        assert counts[EVENT_SQL_INJECTION] == 2
        assert counts[EVENT_SYSTEM] == 1

    def test_the_recent_listing_hides_the_payload(self, events):
        events.record(
            SecurityEvent(
                event_type=EVENT_SQL_INJECTION,
                source="Registration Form",
                payload="secret payload",
            )
        )

        listed = events.recent(limit=5)

        assert "payload" not in listed[0]
        assert listed[0]["attack_type"] == "SQL Injection Attempt"

    def test_the_timeline_groups_the_events_by_day(self, events):
        events.record(SecurityEvent(event_type=EVENT_SYSTEM, source="A"))
        events.record(SecurityEvent(event_type=EVENT_SYSTEM, source="B"))

        timeline = events.timeline(days=7)

        assert timeline
        assert sum(row["total"] for row in timeline) == 2

    def test_the_attack_categories_are_ranked(self, events):
        events.record(
            SecurityEvent(
                event_type=EVENT_SQL_INJECTION,
                source="A",
                category="Boolean Tautology",
            )
        )
        events.record(
            SecurityEvent(
                event_type=EVENT_SQL_INJECTION,
                source="A",
                category="Boolean Tautology",
            )
        )
        events.record(
            SecurityEvent(
                event_type=EVENT_SQL_INJECTION,
                source="A",
                category="Union Exfiltration",
            )
        )

        categories = events.top_attack_categories(limit=5)

        assert categories[0]["category"] == "Boolean Tautology"
        assert categories[0]["total"] == 2


class TestFormatting:
    def test_a_datetime_is_rendered(self):
        value = datetime(2026, 1, 2, 15, 30, tzinfo=UTC)
        assert format_timestamp(value) == "02 Jan 2026, 03:30 PM"

    def test_a_missing_value_becomes_not_available(self):
        assert format_timestamp(None) == "N/A"
