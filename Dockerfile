# syntax=docker/dockerfile:1

# ===================================================================
# SQLShield - multi stage production image
#
# The image is built without a package manager: every dependency ships a
# manylinux wheel, so the build only needs pip.
# ===================================================================

FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

COPY requirements.txt .

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt


# -------------------------------------------------------------------
# Runtime
# -------------------------------------------------------------------

FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    FLASK_ENV=production \
    PORT=8000

RUN groupadd --system --gid 1001 sqlshield \
    && useradd --system --uid 1001 --gid sqlshield --create-home sqlshield

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app

COPY --chown=sqlshield:sqlshield app.py wsgi.py ./
COPY --chown=sqlshield:sqlshield sqlshield ./sqlshield
COPY --chown=sqlshield:sqlshield templates ./templates
COPY --chown=sqlshield:sqlshield static ./static
COPY --chown=sqlshield:sqlshield deploy/gunicorn.conf.py ./deploy/gunicorn.conf.py
COPY --chown=sqlshield:sqlshield pyproject.toml ./

USER sqlshield

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT','8000') + '/health/live', timeout=4).status == 200 else 1)"

CMD ["gunicorn", "--config", "deploy/gunicorn.conf.py", "wsgi:application"]
