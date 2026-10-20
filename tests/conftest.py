"""Shared pytest fixtures.

The environment is configured before the application package is imported
because the configuration classes read the process environment at import
time.
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault("FLASK_ENV", "testing")
os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("MONGO_URI", "mongomock://localhost")
os.environ.setdefault(
    "AES_KEY",
    base64.urlsafe_b64encode(b"0123456789abcdef0123456789abcdef").decode(),
)
os.environ.setdefault("CAPABILITY_CODE", "test-capability-code")
os.environ.setdefault("LOG_LEVEL", "WARNING")
os.environ.setdefault("RATELIMIT_ENABLED", "false")
os.environ.setdefault("TALISMAN_ENABLED", "false")

import pytest  # noqa: E402

from sqlshield import create_app  # noqa: E402

VALID_REGISTRATION = {
    "name": "Sunny Kumar",
    "email": "sunny@example.com",
    "password": "Sup3rSecret!",
    "capability_code": "test-capability-code",
}


@pytest.fixture()
def app():
    """A fresh application backed by an in-memory database."""
    application = create_app("testing")
    yield application
    application.extensions["mongo"].close()


@pytest.fixture()
def client(app):
    """A test client for the application."""
    return app.test_client()


@pytest.fixture()
def registration_payload():
    """A payload that passes every security layer."""
    return dict(VALID_REGISTRATION)


@pytest.fixture()
def repository(app):
    """The user repository of the application."""
    return app.extensions["user_repository"]


@pytest.fixture()
def events(app):
    """The security event repository of the application."""
    return app.extensions["event_repository"]
