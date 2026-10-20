# Security Policy

SQLShield is a security product, so vulnerabilities are handled with care.

---

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately so a fix can be prepared before the details are
published.

| | |
|---|---|
| Contact | kumarsunny33460@gmail.com |
| Response time | Acknowledgement within 72 hours |
| Disclosure | Coordinated disclosure, credit to the reporter unless they prefer otherwise |

Please include:

* the affected component (`sqlshield/security`, `sqlshield/api`, the data layer)
* the steps required to reproduce it
* the impact you observed
* any suggested remediation

Please test only against infrastructure you own or have permission to test.

---

## Scope

In scope:

* the detection engine bypassing a malicious payload
* the capability verification being bypassed
* the encryption being reversible without the key, or the key handling being unsafe
* sensitive data leaking through an API response, a log record or the dashboard
* an authentication or authorisation weakness

Out of scope:

* reports that require an already-compromised host or a leaked secret
* the absence of a specific security header that Talisman sets by default
* findings that only exist in a development configuration
* denial of service through deliberate volumetric attacks

---

## Security design

The controls that protect the application are documented in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). The most important ones:

| Control | Implementation |
|---------|----------------|
| Injection detection | Scored rules with input normalisation, `sqlshield/security/detector.py` |
| Authorisation | Capability code, constant time comparison, lockout |
| Password storage | PBKDF2-HMAC-SHA256, 600 000 iterations, never reversible |
| Data at rest | AES-256-GCM, random nonce per record, versioned key envelope |
| Ciphertext integrity | GCM authentication tag plus optional field binding through the AAD |
| Transport | TLS at the platform, HSTS enforced by Talisman in production |
| Headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` |
| Rate limiting | Flask-Limiter, per route, per client |
| Audit trail | Every security event stored with a request id |
| Secret management | Environment variables only, never committed, `.env` is git ignored |

---

## Reporting security events

If the application detects an attack, the event is recorded in the
`AttackLogs` collection with the category, the severity, the score and the
request id. The payload is stored for forensics but is excluded from every
API response, so an attacker never learns what was logged.

---

## Deployment checklist

Before running SQLShield in production:

- [ ] `FLASK_ENV=production`
- [ ] `SECRET_KEY` set to a long random value
- [ ] `AES_KEYS` set with at least one 256 bit key
- [ ] `FINGERPRINT_KEY` set so the email fingerprints survive a key rotation
- [ ] `CAPABILITY_CODES` set, or `CAPABILITY_CODE_SHA256` used instead
- [ ] The plaintext capability code is not present in the environment
- [ ] `TALISMAN_FORCE_HTTPS=true`
- [ ] `TRUSTED_PROXY_COUNT` matches the number of proxy hops
- [ ] `RATELIMIT_STORAGE_URI` points at Redis when running more than one instance
- [ ] `LOG_JSON=true` so the audit trail is machine readable
- [ ] The MongoDB network access list only allows the platform addresses
- [ ] `/health/ready` returns `200`

---

## Dependency policy

Runtime dependencies are pinned to exact versions in `requirements.txt` and
reviewed through the pull request process. The GitHub Actions workflow
installs the pinned set, runs the full quality gate and builds the container
image on every change.

Run `pip list --outdated` periodically and open a dedicated pull request for
an upgrade so the change stays reviewable.
