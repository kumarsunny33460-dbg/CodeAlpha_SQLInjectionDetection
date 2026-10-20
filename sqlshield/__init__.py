"""SQLShield - SQL injection detection and secure data protection."""

from __future__ import annotations

from .config import resolve_config
from .factory import create_app

__all__ = ["create_app", "resolve_config", "__version__"]

__version__ = "2.0.0"
