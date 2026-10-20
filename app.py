"""Application entry point.

The real implementation lives in the :mod:`sqlshield` package. This module
keeps the original import path working so that ``flask run``, ``python app.py``
and ``gunicorn app:app`` continue to function without changes.
"""

from __future__ import annotations

import os

from dotenv import load_dotenv

from sqlshield import create_app

load_dotenv()

app = create_app(os.getenv("FLASK_ENV"))


if __name__ == "__main__":
    print("=" * 60)
    print("SQLSHIELD - SQL INJECTION DETECTION & SECURE DATA PROTECTION")
    print("Developed by Sunny Kumar")
    print("=" * 60)

    app.run(
        host=os.getenv("HOST", "0.0.0.0"),  # noqa: S104 - containers bind every interface
        port=int(os.getenv("PORT", 5000)),
        debug=app.config.get("DEBUG", False),
    )
