"""WSGI entry point for production servers.

gunicorn wsgi:application
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

from sqlshield import create_app

load_dotenv()

application = create_app(os.getenv("FLASK_ENV", "production"))
app = application

if __name__ == "__main__":
    application.run(host="0.0.0.0", port=int(os.getenv("PORT", 8000)))  # noqa: S104
