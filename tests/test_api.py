"""Tests for the HTTP layer."""

from __future__ import annotations

from sqlshield.db.repositories import (
    EVENT_SQL_INJECTION,
    EVENT_UNAUTHORIZED_ACCESS,
    EVENT_VALIDATION_ERROR,
)


class TestRegistration:
    def test_a_valid_registration_succeeds(self, client, registration_payload):
        response = client.post("/api/v1/register", json=registration_payload)

        assert response.status_code == 201
        body = response.get_json()
        assert body["success"] is True
        assert "AES-256" in body["message"]
        assert body["request_id"]

    def test_the_legacy_endpoint_still_works(self, client, registration_payload):
        response = client.post("/register", json=registration_payload)
        assert response.status_code == 201
        assert response.get_json()["success"] is True

    def test_the_record_is_stored_encrypted(self, client, app, registration_payload):
        client.post("/api/v1/register", json=registration_payload)

        collection = app.extensions["mongo"].users
        document = collection.find_one({})

        assert document is not None
        assert "sunny@example.com" not in document["email"]
        assert document["email"].startswith("enc:")
        assert document["password_hash"].startswith("pbkdf2_sha256$")
        assert "Sup3rSecret!" not in str(document)

    def test_a_sql_injection_is_blocked(self, client, registration_payload):
        registration_payload["name"] = "' OR '1'='1"

        response = client.post("/api/v1/register", json=registration_payload)

        assert response.status_code == 403
        body = response.get_json()
        assert body["success"] is False
        assert "SQL Injection" in body["message"]
        assert body["detection"]["is_injection"] is True
        assert body["detection"]["score"] >= 40

    def test_a_blocked_request_is_not_stored(self, client, app, registration_payload):
        registration_payload["name"] = "1 UNION SELECT NULL --"

        client.post("/api/v1/register", json=registration_payload)

        assert app.extensions["mongo"].users.count_documents({}) == 0

    def test_the_attack_is_logged(self, client, events, registration_payload):
        registration_payload["email"] = "admin' OR 1=1 --"

        client.post("/api/v1/register", json=registration_payload)

        assert events.count(EVENT_SQL_INJECTION) == 1
        assert events.count(EVENT_UNAUTHORIZED_ACCESS) == 0

    def test_an_invalid_capability_code_is_denied(self, client, registration_payload):
        registration_payload["capability_code"] = "wrong-code"

        response = client.post("/api/v1/register", json=registration_payload)

        assert response.status_code == 403
        assert "Capability Code" in response.get_json()["message"]

    def test_the_denied_attempt_is_logged(self, client, events, registration_payload):
        registration_payload["capability_code"] = "wrong-code"

        client.post("/api/v1/register", json=registration_payload)

        assert events.count(EVENT_UNAUTHORIZED_ACCESS) == 1

    def test_an_invalid_email_is_rejected(self, client, registration_payload):
        registration_payload["email"] = "not-an-email"

        response = client.post("/api/v1/register", json=registration_payload)

        assert response.status_code == 400
        assert response.get_json()["success"] is False

    def test_a_short_password_is_rejected(self, client, registration_payload):
        registration_payload["password"] = "abc"

        response = client.post("/api/v1/register", json=registration_payload)

        assert response.status_code == 400
        assert "8 characters" in response.get_json()["message"]

    def test_missing_fields_are_reported(self, client):
        response = client.post("/api/v1/register", json={})

        assert response.status_code == 400
        assert response.get_json()["success"] is False

    def test_a_non_json_body_is_rejected(self, client):
        response = client.post(
            "/api/v1/register",
            data="name=sunny",
            content_type="application/x-www-form-urlencoded",
        )

        assert response.status_code == 400
        assert "JSON" in response.get_json()["message"]

    def test_the_validation_failure_is_logged(self, client, events):
        client.post("/api/v1/register", json={"name": "A"})

        assert events.count(EVENT_VALIDATION_ERROR) == 1

    def test_a_duplicate_email_is_rejected(self, client, registration_payload):
        client.post("/api/v1/register", json=registration_payload)

        response = client.post("/api/v1/register", json=registration_payload)

        assert response.status_code == 409
        assert "already exists" in response.get_json()["message"]


class TestDashboard:
    def test_the_dashboard_returns_the_statistics(self, client):
        response = client.get("/api/v1/dashboard")

        assert response.status_code == 200
        data = response.get_json()["data"]
        assert data["statistics"]["total_users"] == 0
        assert "recent_users" in data
        assert "recent_logs" in data

    def test_the_legacy_dashboard_still_works(self, client):
        response = client.get("/api/dashboard")
        assert response.status_code == 200
        assert response.get_json()["success"] is True

    def test_the_dashboard_counts_the_records(self, client, app, registration_payload):
        client.post("/api/v1/register", json=registration_payload)

        data = client.get("/api/v1/dashboard").get_json()["data"]

        assert data["statistics"]["total_users"] == 1
        assert len(data["recent_users"]) == 1
        assert data["recent_users"][0]["status"] == "AES-256 Encrypted"

    def test_the_dashboard_never_exposes_the_sensitive_fields(self, client, app):
        client.post(
            "/api/v1/register",
            json={
                "name": "Sunny Kumar",
                "email": "sunny@example.com",
                "password": "Sup3rSecret!",
                "capability_code": "test-capability-code",
            },
        )

        data = client.get("/api/v1/dashboard").get_json()["data"]

        assert "password" not in data["recent_users"][0]
        assert "email" not in data["recent_users"][0]


class TestSecurityEvents:
    def test_the_events_endpoint_lists_the_recorded_events(
        self, client, registration_payload
    ):
        registration_payload["name"] = "' OR 1=1 --"
        client.post("/api/v1/register", json=registration_payload)

        response = client.get("/api/v1/security/events")

        assert response.status_code == 200
        events = response.get_json()["data"]["events"]
        assert len(events) == 1
        assert events[0]["event_type"] == EVENT_SQL_INJECTION

    def test_the_event_payload_is_never_exposed(self, client, registration_payload):
        registration_payload["name"] = "' OR 1=1 --"
        client.post("/api/v1/register", json=registration_payload)

        events = client.get("/api/v1/security/events").get_json()["data"]["events"]

        assert "payload" not in events[0]

    def test_the_detect_endpoint_scores_a_payload(self, client):
        response = client.post(
            "/api/v1/security/detect",
            json={"value": "' OR 1=1 --", "field": "name"},
        )

        assert response.status_code == 200
        data = response.get_json()["data"]
        assert data["is_injection"] is True
        assert data["score"] >= 40

    def test_the_detect_endpoint_accepts_benign_input(self, client):
        response = client.post(
            "/api/v1/security/detect",
            json={"value": "Sunny Kumar", "field": "name"},
        )

        assert response.get_json()["data"]["is_injection"] is False

    def test_the_detect_endpoint_rejects_an_empty_payload(self, client):
        response = client.post("/api/v1/security/detect", json={})

        assert response.status_code == 400
        assert response.get_json()["success"] is False

    def test_the_detect_endpoint_rejects_a_non_json_body(self, client):
        response = client.post(
            "/api/v1/security/detect",
            data="value=test",
            content_type="application/x-www-form-urlencoded",
        )

        assert response.status_code == 400

    def test_the_timeline_endpoint_returns_the_daily_counts(self, client):
        response = client.get("/api/v1/security/timeline")

        assert response.status_code == 200
        assert "timeline" in response.get_json()["data"]

    def test_the_timeline_endpoint_covers_the_recorded_events(
        self, client, registration_payload
    ):
        registration_payload["name"] = "' OR 1=1 --"
        client.post("/api/v1/register", json=registration_payload)

        timeline = client.get("/api/v1/security/timeline").get_json()["data"]["timeline"]

        assert timeline
        assert sum(row["total"] for row in timeline) == 1

    def test_the_timeline_accepts_a_day_count(self, client):
        response = client.get("/api/v1/security/timeline?days=30")

        assert response.status_code == 200

    def test_the_timeline_ignores_an_invalid_day_count(self, client):
        response = client.get("/api/v1/security/timeline?days=abc")

        assert response.status_code == 200

    def test_the_event_limit_is_capped(self, client):
        response = client.get("/api/v1/security/events?limit=100000")

        assert response.status_code == 200
        assert response.get_json()["data"]["count"] <= 200

    def test_an_invalid_event_limit_falls_back_to_the_default(self, client):
        response = client.get("/api/v1/security/events?limit=abc")

        assert response.status_code == 200


class TestHealth:
    def test_the_liveness_probe_is_always_up(self, client):
        response = client.get("/health/live")
        assert response.status_code == 200
        assert response.get_json()["data"]["status"] == "alive"

    def test_the_readiness_probe_reports_the_database(self, client):
        response = client.get("/health/ready")
        assert response.status_code == 200
        assert response.get_json()["data"]["database"]["connected"] is True

    def test_the_combined_health_payload_is_available(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.get_json()["data"]
        assert "liveness" in data
        assert data["encryption"]["configured"] is True


class TestErrorHandling:
    def test_an_unknown_page_returns_json(self, client):
        response = client.get("/does-not-exist")
        assert response.status_code == 404
        assert response.get_json()["success"] is False

    def test_the_request_id_is_returned_in_the_header(self, client):
        response = client.get("/health/live")
        assert response.headers.get("X-Request-ID")

    def test_a_supplied_request_id_is_echoed(self, client):
        response = client.get("/health/live", headers={"X-Request-ID": "abc123"})
        assert response.headers.get("X-Request-ID") == "abc123"

    def test_the_security_headers_are_applied(self, client):
        response = client.get("/health/live")
        assert response.headers.get("X-Content-Type-Options") == "nosniff"


class TestWebInterface:
    def test_the_home_page_is_rendered(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert b"SQLShield" in response.data


class TestEntryPoints:
    """The module level entry points must build a working application."""

    def test_the_development_entry_point_exposes_an_app(self):
        import app as development_entry_point

        assert development_entry_point.app is not None
        assert development_entry_point.app.test_client().get("/").status_code == 200

    def test_the_production_entry_point_exposes_an_application(self):
        import wsgi as production_entry_point

        assert production_entry_point.application is not None
        assert production_entry_point.app is production_entry_point.application
