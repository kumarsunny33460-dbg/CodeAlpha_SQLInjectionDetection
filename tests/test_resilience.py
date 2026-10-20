"""Tests for the resilience behaviour.

The application must stay usable when the database is missing or
unreachable, and it must never leak an internal error to the client.
"""

from __future__ import annotations

import pytest

from sqlshield import create_app
from sqlshield.db.mongo import DatabaseUnavailable, MongoManager, UnavailableCollection


@pytest.fixture()
def degraded_app():
    """An application whose database cannot be reached."""
    application = create_app(
        "testing",
        config_overrides={
            "MONGO_URI": "",
            "DATABASE_NAME": "SQLInjectionSecurity",
        },
    )
    yield application
    application.extensions["mongo"].close()


class TestDegradedMode:
    def test_the_application_still_boots(self, degraded_app):
        assert degraded_app is not None

    def test_the_database_is_reported_as_disconnected(self, degraded_app):
        mongo = degraded_app.extensions["mongo"]

        assert mongo.is_connected is False
        assert mongo.last_error

    def test_the_liveness_probe_stays_up(self, degraded_app):
        response = degraded_app.test_client().get("/health/live")

        assert response.status_code == 200

    def test_the_readiness_probe_reports_degraded(self, degraded_app):
        response = degraded_app.test_client().get("/health/ready")

        assert response.status_code == 503
        assert response.get_json()["data"]["status"] == "degraded"

    def test_the_health_payload_explains_the_failure(self, degraded_app):
        response = degraded_app.test_client().get("/health/ready")
        database = response.get_json()["data"]["database"]

        assert database["connected"] is False
        assert database["error"]

    def test_the_home_page_is_still_served(self, degraded_app):
        assert degraded_app.test_client().get("/").status_code == 200

    def test_the_dashboard_returns_a_clean_error(self, degraded_app):
        response = degraded_app.test_client().get("/api/v1/dashboard")

        assert response.status_code == 500
        assert response.get_json()["success"] is False

    def test_the_registration_endpoint_still_answers(self, degraded_app):
        response = degraded_app.test_client().post(
            "/api/v1/register",
            json={
                "name": "Sunny Kumar",
                "email": "sunny@example.com",
                "password": "Sup3rSecret!",
                "capability_code": "test-capability-code",
            },
        )

        assert response.status_code in {201, 403, 500}
        assert response.get_json()["success"] is False

    def test_the_repository_raises_a_clear_error(self, degraded_app):
        repository = degraded_app.extensions["user_repository"]

        with pytest.raises(DatabaseUnavailable):
            repository.count()

    def test_the_error_is_contained_in_the_response(self, degraded_app):
        response = degraded_app.test_client().get("/api/v1/dashboard")

        assert "Traceback" not in response.get_data(as_text=True)


class TestUnavailableCollection:
    def test_every_operation_raises(self):
        placeholder = UnavailableCollection("no database")

        with pytest.raises(DatabaseUnavailable):
            placeholder.find_one({})

        with pytest.raises(DatabaseUnavailable):
            placeholder.insert_one({})

        with pytest.raises(DatabaseUnavailable):
            placeholder.count_documents({})

    def test_the_reason_is_carried(self):
        placeholder = UnavailableCollection("custom reason")

        with pytest.raises(DatabaseUnavailable, match="custom reason"):
            placeholder.find_one({})


class TestMongoManager:
    def test_ping_without_a_client_returns_false(self):
        manager = MongoManager()

        assert manager.ping() is False
        assert manager.last_error

    def test_accessing_the_database_before_init_raises(self):
        manager = MongoManager()

        with pytest.raises(DatabaseUnavailable):
            _ = manager.database

    def test_accessing_the_client_before_init_raises(self):
        manager = MongoManager()

        with pytest.raises(DatabaseUnavailable):
            _ = manager.client

    def test_closing_an_uninitialised_manager_is_safe(self):
        MongoManager().close()

    def test_the_indexes_are_created_on_start_up(self, app):
        mongo = app.extensions["mongo"]

        user_indexes = mongo.users.index_information()
        event_indexes = mongo.events.index_information()

        assert "users_email_fingerprint" in user_indexes
        assert "events_timestamp" in event_indexes
        assert user_indexes["users_email_fingerprint"]["unique"] is True


class TestErrorEnvelope:
    def test_an_unknown_route_returns_a_json_error(self, client):
        response = client.get("/definitely-not-a-route")

        assert response.status_code == 404
        body = response.get_json()
        assert body["success"] is False
        assert body["type"] == "warning"
        assert body["request_id"]

    def test_the_wrong_method_returns_a_json_error(self, client):
        response = client.get("/api/v1/register")

        assert response.status_code == 405
        assert response.get_json()["success"] is False

    def test_an_oversized_body_is_rejected(self, app, client):
        app.config["MAX_CONTENT_LENGTH"] = 128

        response = client.post(
            "/api/v1/register",
            data="x" * 512,
            content_type="application/json",
        )

        assert response.status_code == 413
        assert response.get_json()["success"] is False
