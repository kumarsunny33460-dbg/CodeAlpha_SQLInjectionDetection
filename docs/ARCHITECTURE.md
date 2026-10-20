# Architecture

This document describes how SQLShield is put together, why the structure
looks the way it does and how a request travels through the system.

---

## 1. Design principles

1. **The application never imports its infrastructure.** Every module is
   importable without a database, a network or an environment file. The
   application factory is the only place that wires the components together.
2. **A request must never crash the process.** Failures are contained, logged
   and reported as a degraded state rather than an unhandled exception.
3. **Security decisions are explainable.** Every block carries the rules that
   fired, the score and the severity so it can be audited.
4. **Secrets never appear in responses.** Payloads are stored for forensics
   but are excluded from every API projection.

---

## 2. Layer map

```
┌───────────────────────────────────────────────────────────────┐
│  HTTP LAYER            sqlshield/api/*                        │
│  Blueprints, validation of the envelope, rate limits          │
├───────────────────────────────────────────────────────────────┤
│  SERVICE LAYER         sqlshield/services/registration.py     │
│  The security pipeline, orchestration of the layers           │
├───────────────────────────────────────────────────────────────┤
│  DOMAIN LAYER          sqlshield/security/*                   │
│  Detection rules, encryption, capability verification         │
├───────────────────────────────────────────────────────────────┤
│  DATA LAYER            sqlshield/db/*                         │
│  Repositories, connection management, indexes                 │
├───────────────────────────────────────────────────────────────┤
│  INFRASTRUCTURE        config, extensions, logging, errors    │
└───────────────────────────────────────────────────────────────┘
```

Dependencies point downwards only. The domain layer has no knowledge of HTTP
and the data layer has no knowledge of Flask.

---

## 3. Request lifecycle

```
Client
  │
  ▼
ProxyFix                     trust the proxy hop count
  │
  ▼
before_request               assign or adopt the X-Request-ID
  │
  ▼
Blueprints                   Flask-Limiter applies the route limits
  │
  ▼
RegistrationService
  ├── 1. analyse_fields()      detection engine
  ├── 2. validate_registration()  field rules
  ├── 3. CapabilityVerifier.verify()  authorisation
  ├── 4. KeyVault.encrypt()    AES-256-GCM
  │      hash_password()        PBKDF2-HMAC-SHA256
  └── 5. UserRepository.create()   MongoDB
  │
  ▼
Response envelope            success + data + request_id
  │
  ▼
after_request                structured access log, security headers
```

---

## 4. Module map

### `sqlshield/config.py`

Reads the environment once at import time and exposes three configuration
classes: `DevelopmentConfig`, `TestingConfig` and `ProductionConfig`.
`config_value()` accepts either a Flask config object (a dict subclass) or a
plain class, which keeps the helpers usable in both contexts.

### `sqlshield/factory.py`

`create_app()` performs the wiring:

1. resolve the configuration class
2. create the Flask application with the project template and static folders
3. apply `ProxyFix` using `TRUSTED_PROXY_COUNT`
4. initialise the extensions
5. build the key vault and the capability verifier
6. initialise MongoDB and the repositories
7. register the blueprints and the error handlers

### `sqlshield/security/detector.py`

The detection engine. It normalises the value, evaluates the rules that apply
to the field, accumulates a weighted score and applies two statistical
signals (keyword density and quote imbalance).

| Score band | Severity |
|-----------|----------|
| ≥ 90 | critical |
| ≥ 70 | high |
| ≥ 55 | medium |
| ≥ 40 | low |
| < 40 | none (allowed) |

The default block threshold is 40, which is why a bare comment marker (20)
does not block while a tautology (75) does.

### `sqlshield/security/crypto.py`

`KeyVault` holds one or more AES-256 keys. Ciphertexts are stored in a
versioned envelope:

```
enc:<key-id>:<base64(nonce || ciphertext || tag)>
```

* The nonce is random per encryption, so the same plaintext never produces
  the same ciphertext.
* The key id makes rotation possible: `ACTIVE_KEY_ID` chooses the key for new
  records while the others remain valid for decryption.
* `aad` binds the ciphertext to a context string, so a ciphertext produced for
  the email field cannot be replayed into the name field.

`hash_password()` produces `pbkdf2_sha256$<iterations>$<salt>$<hash>` so the
work factor can be raised without invalidating existing records.

### `sqlshield/security/capability.py`

Verifies the capability code with `hmac.compare_digest`, supports several
valid codes and SHA-256 digests, and tracks the failures per client so a
brute force attempt is locked out.

### `sqlshield/db/mongo.py`

`MongoManager` owns the client. The connection is created lazily inside a
`try` block: when MongoDB is unreachable the application still boots and the
readiness probe reports `degraded` instead of the process dying.

Indexes created on start-up:

| Collection | Index | Purpose |
|-----------|-------|---------|
| `SecureUsers` | `created_at` | recent record listing |
| `SecureUsers` | `email_fingerprint` (unique, sparse) | duplicate prevention and lookup without decryption |
| `AttackLogs` | `timestamp` | recent event listing |
| `AttackLogs` | `event_type, timestamp` | per type counters |
| `AttackLogs` | `request_id` | trace an event back to a request |

### `sqlshield/db/repositories.py`

`UserRepository` and `EventRepository` own every query shape. The email
fingerprint is an HMAC of the **clear text** address, derived from a dedicated
`FINGERPRINT_KEY` when it is configured, otherwise from the active AES key.
Deriving it from the ciphertext would be useless because every encryption uses
a fresh nonce.

### `sqlshield/services/registration.py`

Implements the pipeline. Detection runs **before** field validation so that a
payload is always recorded as an attack even when it would also fail the
format rules.

---

## 5. Data model

### `SecureUsers`

```json
{
  "_id": "ObjectId",
  "name": "enc:v1:base64...",
  "email": "enc:v1:base64...",
  "email_fingerprint": "hmac-sha256 hex",
  "password_hash": "pbkdf2_sha256$600000$salt$hash",
  "security_status": "AES-256 Encrypted",
  "schema_version": 2,
  "capability_verified": true,
  "request_id": "…",
  "created_at": ISODate
}
```

### `AttackLogs`

```json
{
  "_id": "ObjectId",
  "event_type": "sql_injection",
  "label": "SQL Injection Attempt",
  "category": "Boolean Tautology",
  "severity": "high",
  "score": 75,
  "source": "Registration Form",
  "payload": "' OR '1'='1",
  "ip_address": "203.0.113.4",
  "user_agent": "Mozilla/5.0",
  "request_id": "…",
  "details": { },
  "timestamp": ISODate
}
```

`payload` is stored for forensics but is projected out of every API response.

---

## 6. Reliability

| Failure | Behaviour |
|---------|-----------|
| MongoDB unreachable at start-up | The app boots, `/health/ready` returns 503 with `degraded`, the dashboard reports the failure |
| MongoDB unreachable during a request | The error handler returns a JSON 500, the request id is logged |
| Missing AES key | The app boots and logs a warning, registrations fail with a clear message |
| Missing capability code | The app boots and logs a warning, registrations are denied |
| Rate limit exceeded | HTTP 429 with the standard envelope |

---

## 7. Security controls

| Control | Implementation |
|---------|----------------|
| Injection detection | `sqlshield/security/detector.py` |
| Authorisation | Capability code, constant time, lockout |
| Password storage | PBKDF2-HMAC-SHA256, 600 000 iterations |
| Data at rest | AES-256-GCM with a random nonce |
| Transport | TLS terminated at the platform, HSTS via Talisman |
| Headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` |
| Rate limiting | Flask-Limiter, per route |
| Input validation | Length, format and type checks |
| CORS | Explicit allow list, same origin by default |
| Audit trail | Every security event stored with the request id |
| Secrets | Environment variables only, never committed |

---

## 8. Testing strategy

| Layer | Approach |
|-------|----------|
| Detection engine | Table driven, true and false positive fixtures |
| Cryptography | Round trips, rotation, AAD binding, tamper detection |
| Capability | Verification, lockout, scoping per client |
| Repositories | In-memory MongoDB through `mongomock` |
| HTTP surface | Flask test client, full request and response assertions |
| Configuration | Environment helpers and config resolution |

The suite runs without any external service, which keeps CI fast and
deterministic.
