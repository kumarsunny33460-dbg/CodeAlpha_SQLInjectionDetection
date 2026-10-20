# Configuration reference

Every setting is read from the process environment. Values are resolved once,
when the configuration module is imported.

Copy `.env.example` to `.env` and use it as the starting point.

---

## Application

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_ENV` | `development` | `development`, `testing` or `production` |
| `SECRET_KEY` | — | Flask session secret. Required in production |
| `PORT` | `5000` | Port used by the development server |
| `MAX_CONTENT_LENGTH` | `65536` | Maximum request body size in bytes |
| `TRUSTED_PROXY_COUNT` | `1` | Number of trusted proxy hops for `ProxyFix` |

---

## Database

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGO_URI` | — | Connection string. Required |
| `DATABASE_NAME` | `SQLInjectionSecurity` | Database name |
| `COLLECTION_NAME` | `SecureUsers` | User collection |
| `EVENTS_COLLECTION` | `AttackLogs` | Security event collection |
| `MONGO_CONNECT_TIMEOUT_MS` | `5000` | Socket connect timeout |
| `MONGO_SERVER_SELECTION_TIMEOUT_MS` | `5000` | Server selection timeout |
| `MONGO_SOCKET_TIMEOUT_MS` | `10000` | Socket operation timeout |
| `MONGO_MAX_POOL_SIZE` | `50` | Maximum pooled connections |
| `MONGO_MIN_POOL_SIZE` | `1` | Minimum pooled connections |
| `MONGO_RETRY_WRITES` | `true` | Enable retryable writes |
| `MONGO_AUTO_INDEX` | `true` | Create the indexes on start-up |

Use `mongomock://localhost` as the URI to run against an in-memory database.

---

## Encryption and hashing

| Variable | Default | Description |
|----------|---------|-------------|
| `AES_KEYS` | — | Comma separated `key-id:base64` pairs |
| `AES_KEY` | — | Legacy single key, used when `AES_KEYS` is empty |
| `ACTIVE_KEY_ID` | `v1` | Key used for new records |
| `FINGERPRINT_KEY` | derived | Stable key for the email fingerprint |
| `PBKDF2_ITERATIONS` | `600000` | Password hashing work factor |

Generate a key:

```bash
python -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

`FINGERPRINT_KEY` should be set in production. Without it the email
fingerprint is derived from the active AES key, so rotating the encryption key
also changes every fingerprint.

---

## Capability verification

| Variable | Default | Description |
|----------|---------|-------------|
| `CAPABILITY_CODES` | — | Comma separated accepted codes |
| `CAPABILITY_CODE` | — | Legacy single code |
| `CAPABILITY_CODE_SHA256` | — | SHA-256 digest of the code |
| `CAPABILITY_MAX_ATTEMPTS` | `5` | Failures before the lockout |
| `CAPABILITY_LOCKOUT_SECONDS` | `300` | Lockout duration |

The SHA-256 variant keeps the plaintext secret out of the environment:

```bash
python -c "import hashlib; print(hashlib.sha256(b'my-code').hexdigest())"
```

---

## Detection engine

| Variable | Default | Description |
|----------|---------|-------------|
| `SQLI_BLOCK_THRESHOLD` | `40` | Score at which a request is blocked |
| `SQLI_MAX_FIELD_LENGTH` | `512` | Maximum accepted field length |
| `SQLI_LOG_PAYLOAD_MAX` | `500` | Maximum stored payload length |

Severity bands follow from the score:

| Score | Severity |
|-------|----------|
| ≥ 90 | critical |
| ≥ 70 | high |
| ≥ 55 | medium |
| ≥ 40 | low |
| < 40 | none |

Lowering the threshold to `0` blocks everything, which is useful for testing.

---

## Rate limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `RATELIMIT_ENABLED` | `true` | Enable the limiter |
| `RATELIMIT_STORAGE_URI` | `memory://` | Storage backend |
| `RATELIMIT_DEFAULT` | `120 per minute` | Global limit |
| `RATELIMIT_REGISTRATION` | `10 per minute` | Registration limit |
| `RATELIMIT_DASHBOARD` | `60 per minute` | Read limit |

Use `redis://` for `RATELIMIT_STORAGE_URI` when running more than one
instance, otherwise the counters are per process.

---

## Security headers and CORS

| Variable | Default | Description |
|----------|---------|-------------|
| `TALISMAN_ENABLED` | `true` | Enable the security headers |
| `TALISMAN_FORCE_HTTPS` | `true` | Redirect to HTTPS, enable HSTS |
| `TALISMAN_CSP` | see below | The Content Security Policy |
| `CORS_ORIGINS` | empty | Allowed origins, same origin by default |

Default policy:

```
default-src 'self';
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com;
font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com;
img-src 'self' data:;
connect-src 'self'
```

Set `TALISMAN_FORCE_HTTPS=false` for local HTTP development.

---

## Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `LOG_JSON` | `false` | Emit newline delimited JSON records |
| `LOG_DIR` | — | Directory for the rotating log file |
| `LOG_MAX_BYTES` | `5242880` | Rotation size in bytes |
| `LOG_BACKUP_COUNT` | `5` | Number of rotated files kept |
| `LOG_REQUESTS` | `true` | Log every request |

Production defaults to JSON output. Each record carries the request id so a
single request can be traced end to end.

---

## Environment differences

| Setting | development | testing | production |
|---------|-------------|---------|------------|
| `DEBUG` | `true` | `false` | `false` |
| `LOG_JSON` | `false` | `false` | `true` |
| `TALISMAN_ENABLED` | `false` | `false` | `true` |
| `TALISMAN_FORCE_HTTPS` | `false` | `false` | `true` |
| `RATELIMIT_ENABLED` | `false` | `false` | `true` |
| `SESSION_COOKIE_SECURE` | `false` | `false` | `true` |
| `MONGO_URI` | from `.env` | `mongomock://localhost` | from `.env` |
| `PBKDF2_ITERATIONS` | `600000` | `1000` | `600000` |
