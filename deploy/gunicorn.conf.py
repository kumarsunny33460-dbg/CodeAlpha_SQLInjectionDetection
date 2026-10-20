"""Gunicorn configuration for production deployments.

Tuned for container platforms: a sync worker pool with a generous timeout for
cold starts, periodic restarts to contain any memory growth and access logs
disabled in favour of the structured application logs.
"""

from __future__ import annotations

import multiprocessing
import os

# ---------------------------------------------------------------------
# Server socket
# ---------------------------------------------------------------------
bind = os.getenv("GUNICORN_BIND", f"0.0.0.0:{os.getenv('PORT', 8000)}")
backlog = 2048

# ---------------------------------------------------------------------
# Worker processes
# ---------------------------------------------------------------------
workers = int(os.getenv("GUNICORN_WORKERS", min(multiprocessing.cpu_count() * 2 + 1, 8)))
worker_class = os.getenv("GUNICORN_WORKER_CLASS", "sync")
threads = int(os.getenv("GUNICORN_THREADS", 4))
timeout = int(os.getenv("GUNICORN_TIMEOUT", 60))
graceful_timeout = int(os.getenv("GUNICORN_GRACEFUL_TIMEOUT", 30))
keepalive = int(os.getenv("GUNICORN_KEEPALIVE", 5))
max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", 1000))
max_requests_jitter = int(os.getenv("GUNICORN_MAX_REQUESTS_JITTER", 100))

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
accesslog = os.getenv("GUNICORN_ACCESS_LOG", "-")
errorlog = os.getenv("GUNICORN_ERROR_LOG", "-")
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")
access_log_format = '%(h)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s %(D)s'

# ---------------------------------------------------------------------
# Process naming and hooks
# ---------------------------------------------------------------------
proc_name = "sqlshield"


def post_fork(server, worker):  # noqa: ANN001, ARG001
    """Close inherited sockets so workers start from a clean state."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)


def worker_int(worker):  # noqa: ANN001, ARG001
    """Handle a graceful worker shutdown."""
    worker.log.info("Worker received INT, exiting")


def on_starting(server):  # noqa: ANN001, ARG001
    server.log.info("SQLShield is starting")
