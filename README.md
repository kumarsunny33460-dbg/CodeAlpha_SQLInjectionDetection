# 🛡️ SQLShield — SQL Injection Detection & Secure Data Protection

<div align="center">

![Cybersecurity](https://img.shields.io/badge/Cybersecurity-SQL%20Injection%20Detection-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.12-Flask-blue?style=for-the-badge)
![Cloud](https://img.shields.io/badge/Cloud-MongoDB%20Atlas%20%2B%20Docker-green?style=for-the-badge)
![Security](https://img.shields.io/badge/Security-AES--256--GCM%20%2B%20PBKDF2-purple?style=for-the-badge)
![CI](https://img.shields.io/badge/CI-GitHub%20Actions-success?style=for-the-badge)

</div>

<h3 align="center">
Cloud-native security platform that detects SQL injection attacks,
encrypts sensitive records and monitors every security event.
</h3>

---

## 📌 Overview

**SQLShield** is a production-grade, cloud-ready security platform built with
Flask and MongoDB Atlas. It combines a layered detection engine with
authenticated encryption and a real-time monitoring dashboard.

```
🔍 SQL Injection Detection  ─┐
                            ├─►  🚫 Block  ─►  📊 Log  ─►  📈 Monitor
🔑 Capability Verification  ─┘
            │
            ▼
   🔐 AES-256-GCM Encryption
            │
            ▼
   ☁️  MongoDB Atlas Storage
```
🔴 **[Live Demo](https://sqlshield.onrender.com/)**

### What makes it production ready

| Area | Before | Now |
|------|--------|-----|
| **Detection** | 12 raw regexes, blocked on any `#` | 18 scored rules, field-scoped, normalisation + obfuscation handling |
| **Passwords** | Stored as reversible ciphertext | PBKDF2-HMAC-SHA256, 600 000 iterations, constant-time verify |
| **Capability code** | `==` comparison | `hmac.compare_digest`, SHA-256 digests, lockout after N failures |
| **Encryption** | Single fixed key | Versioned envelope, multi-key rotation, GCM AAD binding |
| **Structure** | Flat modules | `sqlshield/` package, app factory, blueprints, services, repositories |
| **API** | Two routes, no envelope | Versioned `/api/v1` + legacy aliases, shared JSON envelope, request IDs |
| **Reliability** | Import-time DB connection | Lazy pool, timeouts, graceful degradation, health probes |
| **Observability** | `print()` | Structured JSON logs, request correlation, audit trail |
| **Hardening** | None | Rate limiting, security headers, CORS, input validation, duplicate protection |
| **Delivery** | `Procfile` pointing at a missing object | Docker, Compose, Render, Railway, Fly.io, GitHub Actions CI |
| **Quality** | No tests | 205 pytest cases, Ruff, mypy, pre-commit |

---

## 🚀 Quick start

### One command (Windows)

```powershell
./scripts/dev.ps1 setup
```

That creates the virtual environment, installs the dependencies, creates `.env`
and starts the whole stack in Docker. Open <http://127.0.0.1:8000/>.

### One command (macOS / Linux)

```bash
git clone https://github.com/kumarsunny33460-dbg/CodeAlpha_SQLInjectionDetection.git
cd CodeAlpha_SQLInjectionDetection

cp .env.example .env
docker compose up --build
```

Open <http://127.0.0.1:8000/>. This starts the application together with a
local MongoDB, so no cloud account is needed.

### Local development

```bash
python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux

pip install -r requirements-dev.txt
cp .env.example .env            # then fill in the values
python app.py
```

Open <http://127.0.0.1:5000/>.

### The database

The default `MONGO_URI` points at a local MongoDB so the project works out of
the box. Choose whichever suits you:

| Option | Command |
|--------|---------|
| Full Docker stack | `docker compose up --build` |
| Local MongoDB only | `docker run -d --name sqlshield-mongo -p 27017:27017 mongo:7` |
| MongoDB Atlas | Put the connection string from the Atlas dashboard into `MONGO_URI` |

> The previous Atlas cluster no longer exists, so its host does not resolve.
> The old URI is kept in `.env` as a comment. Create a new cluster and replace
> the URI when you want to use the cloud database.

### Windows helper commands

```powershell
./scripts/dev.ps1 setup      # bootstrap and start the stack
./scripts/dev.ps1 run        # development server
./scripts/dev.ps1 test       # test suite
./scripts/dev.ps1 lint       # linter
./scripts/dev.ps1 check      # lint + types + tests
./scripts/dev.ps1 docker     # rebuild the Docker stack
```

---

## 🔑 Configuration

Every setting is read from the environment. Copy `.env.example` to `.env` and
fill in the values. See [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) for the
complete reference.

### Required

| Variable | Description |
|----------|-------------|
| `MONGO_URI` | MongoDB Atlas connection string |
| `AES_KEYS` | Encryption keys as `key-id:base64` pairs |
| `CAPABILITY_CODES` | Accepted capability code(s) |
| `SECRET_KEY` | Flask session secret |

### Generate a key

```bash
python -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

### Key rotation

`AES_KEYS` accepts several keys. `ACTIVE_KEY_ID` selects the key used for new
records; every other key stays valid for decryption, so rotation needs no
downtime and no migration.

```env
AES_KEYS=v1:OLD_KEY_BASE64,v2:NEW_KEY_BASE64
ACTIVE_KEY_ID=v2
```

---

## 🔒 Security workflow

```
                  User Input
                       │
                       ▼
        ┌──────────────────────────┐
        │  1. SQL Injection Scan   │  normalise → score → block at ≥ 40
        └──────────────────────────┘
                       │ pass
                       ▼
        ┌──────────────────────────┐
        │  2. Field Validation     │  format, length, type
        └──────────────────────────┘
                       │ pass
                       ▼
        ┌──────────────────────────┐
        │  3. Capability Verify    │  constant time + lockout
        └──────────────────────────┘
                       │ pass
                       ▼
        ┌──────────────────────────┐
        │  4. Encrypt & Hash       │  AES-256-GCM + PBKDF2
        └──────────────────────────┘
                       │
                       ▼
        ┌──────────────────────────┐
        │  5. MongoDB Atlas Store  │
        └──────────────────────────┘
                       │
                       ▼
              📊 Dashboard · 📡 Live Feed
```

---

## 🔍 Detection engine

The engine normalises every value before evaluating it, then scores the
matches. A request is blocked when the score reaches the threshold
(`SQLI_BLOCK_THRESHOLD`, default 40).

**Normalisation** — URL decoding (up to three passes), HTML entities, Unicode
NFKC folding, null byte removal, comment stripping.

**Rule categories** — Union Exfiltration, Stacked Query, Remote Command
Execution, Time Based Blind, Boolean Tautology, Schema Manipulation, Data
Manipulation, Schema Discovery, Quote Breach, Blind Extraction, Conditional
Payload, Obfuscation, Comment Manipulation, Encoding Evasion.

**Field scoping** — rules are scoped per field so ordinary data never trips
the engine. `Anne-Marie O'Brien` and `C# developer` are accepted, while
`admin' OR 1=1 --` is blocked.

```python
from sqlshield.security.detector import analyse

result = analyse("admin' OR 1=1 --", field_name="name")
result.is_injection  # True
result.score  # 75
result.severity  # 'high'
result.matched_rules  # ('boolean_tautology', 'quote_breach', ...)
```

---

## 🔌 API

All responses share one envelope:

```json
{ "success": true, "data": { }, "request_id": "3f9c…" }
{ "success": false, "type": "danger", "message": "…", "request_id": "3f9c…" }
```

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/` | Single page application |
| `POST` | `/api/v1/register` | Secure registration |
| `POST` | `/api/v1/security/detect` | Score a payload without storing it |
| `GET` | `/api/v1/security/events` | Recent security events |
| `GET` | `/api/v1/security/timeline` | Daily event counts |
| `GET` | `/api/v1/dashboard` | Aggregated dashboard payload |
| `GET` | `/api/v1/health` | Combined health payload |
| `GET` | `/health/live` | Liveness probe |
| `GET` | `/health/ready` | Readiness probe (database aware) |

The v1 routes `POST /register` and `GET /api/dashboard` remain available as
aliases so existing clients keep working.

---

## 🧪 Testing

```bash
pytest                                   # 205 tests
pytest --cov=sqlshield --cov-report=term-missing
```

The suite covers the detection engine, the cryptographic primitives, the
capability verifier, the repositories, the configuration layer and the HTTP
surface. No live database is required: `mongomock` provides an in-memory
MongoDB.

---

## ☁️ Deployment

| Platform | Manifest | Command |
|----------|----------|---------|
| Docker | `Dockerfile` | `gunicorn --config deploy/gunicorn.conf.py wsgi:application` |
| Render | `render.yaml` | Blueprint, one click |
| Railway | `railway.toml` | Nixpacks build |
| Fly.io | `fly.toml` | Container with health checks |
| Heroku | `Procfile` | `gunicorn … wsgi:application` |

The container image is multi stage, runs as a non-root user and ships with a
`HEALTHCHECK` that polls `/health/live`.

```bash
# Docker
docker build -t sqlshield:latest .
docker run -p 8000:8000 --env-file .env sqlshield:latest

# Render
render blueprint launch
```

See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for a step by step walkthrough.

---

## 🛠️ Technology stack

| Technology | Purpose |
|------------|---------|
| Python 3.12 | Backend language |
| Flask 3 | Web framework, application factory |
| Flask-Limiter | Rate limiting |
| Flask-Talisman | Security headers, CSP, HSTS |
| Flask-CORS | CORS policy |
| MongoDB Atlas | Cloud database |
| PyMongo | Database driver |
| Cryptography | AES-256-GCM |
| Gunicorn | Production WSGI server |
| Chart.js | Dashboard charts |
| Bootstrap 5 + Font Awesome | Interface |
| Ruff, mypy, pytest | Quality gates |
| Docker, GitHub Actions | Delivery pipeline |

---

## 📂 Project structure

```
SQLInjectionDetection
├── app.py                    # development entry point
├── wsgi.py                   # production entry point (wsgi:application)
├── sqlshield/
│   ├── __init__.py           # create_app
│   ├── factory.py            # application factory
│   ├── config.py             # environment driven configuration
│   ├── extensions.py         # limiter, talisman, cors
│   ├── logging_config.py     # structured logging, request ids
│   ├── errors.py             # JSON envelope and error handlers
│   ├── schemas.py            # payload validation
│   ├── api/                  # blueprints
│   │   ├── web.py
│   │   ├── registration.py
│   │   ├── dashboard.py
│   │   ├── events.py
│   │   └── health.py
│   ├── security/             # detection, crypto, capability
│   │   ├── rules.py
│   │   ├── detector.py
│   │   ├── crypto.py
│   │   └── capability.py
│   ├── db/                   # persistence
│   │   ├── mongo.py
│   │   └── repositories.py
│   └── services/             # business logic
│       └── registration.py
├── tests/                    # pytest suite
├── deploy/                   # gunicorn configuration
├── templates/ · static/      # interface
├── Dockerfile · docker-compose.yml
├── render.yaml · railway.toml · fly.toml · Procfile
├── pyproject.toml · Makefile · .pre-commit-config.yaml
└── .github/workflows/ci.yml
```

The original module names (`sql_detector.py`, `encryption.py`, `capability.py`,
`database.py`) still exist as thin compatibility shims so existing imports and
scripts keep working.

---

## 🧪 Test scenarios

**Valid registration**

```
Name:            Sunny Kumar
Email:           sunny@example.com
Password:        ********
Capability code: <your code>
```

→ `User data stored securely with AES-256 encryption.`

**SQL injection**

```
Name: ' OR '1'='1
```

→ `SQL Injection Attack Detected. Request Blocked.` (HTTP 403)

**Invalid capability code**

```
Capability code: wrong
```

→ `Invalid Capability Code. Access Denied.` (HTTP 403)

**Duplicate email**

→ `A record already exists for this email address.` (HTTP 409)

---

## 🔮 Future enhancements

- Machine-learning based anomaly detection
- Real-time security email alerts
- Multi-factor authentication and user sessions
- SIEM export of the security event stream
- Automated image scanning in CI
- IP reputation and geo-blocking

---

## 📸 Screenshots

| Screen | File |
|--------|------|
| Home page | `homepage-1.png` |
| Secure registration | `secureregistration.png` |
| Invalid capability code | `invalidcapabilitycode.png` |
| Injection detected | `sqlinjectionattackeddetected.png` |
| Dashboard | `dashboard.png` |

---

## 👨‍💻 Author

**Sunny Kumar** — Computer Science & Engineering

Developed as part of the **CodeAlpha Cloud Computing Internship**.

---

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">

## 🛡️ Detect → Verify → Encrypt → Store → Monitor

**Security first, cloud ready.**

</div>
