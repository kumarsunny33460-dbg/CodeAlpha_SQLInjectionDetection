# Deployment

SQLShield runs anywhere Python runs. The application is stateless, so it
scales horizontally; all durable state lives in MongoDB Atlas.

---

## 1. Before you start

You need:

* a MongoDB database — a local container or a MongoDB Atlas cluster
* a generated AES key
* a capability code
* a `SECRET_KEY`

```bash
python -c "import base64,os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

### Choosing the database

**Local MongoDB (quickest):**

```bash
docker run -d --name sqlshield-mongo -p 27017:27017 mongo:7
```

The default `MONGO_URI=mongodb://127.0.0.1:27017` already points at it.

**MongoDB Atlas:**

Create a cluster in the Atlas dashboard, add a database user and allow the
platform's IP range to reach it. Copy the connection string into `MONGO_URI`.

> The cluster this project previously used no longer exists, so its host does
> not resolve. The old URI is preserved in `.env` as a comment. Create a new
> cluster and replace the URI, then set `MONGO_AUTO_INDEX=true` so the
> indexes are created on the first start.

---

## 2. Docker (any platform)

### Build and run locally

```bash
docker build -t sqlshield:latest .
docker run -d --name sqlshield -p 8000:8000 --env-file .env sqlshield:latest
curl http://127.0.0.1:8000/health/live
```

The image is multi stage, runs as the unprivileged `sqlshield` user and ships
with a `HEALTHCHECK` that polls `/health/live`.

### Docker Compose

```bash
docker compose up --build -d
```

Starts the application together with a local MongoDB, which is handy for a
demo without an Atlas cluster. The `MONGO_URI` in `docker-compose.yml` points
at that container.

---

## 3. Render

1. Push the repository to GitHub
2. In Render, choose **New → Blueprint** and select the repository
3. Render reads `render.yaml` and creates the web service
4. Fill in the values marked `sync: false`: `MONGO_URI`, `CAPABILITY_CODE`
   and `AES_KEYS`
5. Deploy

The service uses `gunicorn --config deploy/gunicorn.conf.py wsgi:application`
and the health check path `/health/live`.

---

## 4. Railway

1. `railway init` and `railway up`
2. Add the variables from `.env.example` under **Variables**
3. `railway.toml` already configures the build and the start command

---

## 5. Fly.io

```bash
fly launch --no-deploy --copy-config
fly secrets set MONGO_URI=... CAPABILITY_CODES=... AES_KEYS=... SECRET_KEY=...
fly deploy
```

`fly.toml` declares the internal port, forces HTTPS and registers both the
liveness and the readiness probes.

---

## 6. Heroku and other Procfile platforms

The `Procfile` starts the application with Gunicorn:

```
web: gunicorn --config deploy/gunicorn.conf.py wsgi:application
```

Set the environment variables through the platform's dashboard.

---

## 7. A bare virtual machine

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export FLASK_ENV=production
export MONGO_URI=...
export AES_KEYS=...
export CAPABILITY_CODES=...
export SECRET_KEY=...

gunicorn --config deploy/gunicorn.conf.py wsgi:application
```

Put Nginx or Caddy in front for TLS and set `TRUSTED_PROXY_COUNT=1` so the
client IP is read from `X-Forwarded-For`.

---

## 8. Environment variables in production

| Variable | Value |
|----------|-------|
| `FLASK_ENV` | `production` |
| `PORT` | `8000` (Render and Fly set this for you) |
| `SECRET_KEY` | long random string |
| `MONGO_URI` | Atlas connection string |
| `AES_KEYS` | `key-id:base64` pairs |
| `ACTIVE_KEY_ID` | the key used for new records |
| `CAPABILITY_CODES` | comma separated list of accepted codes |
| `LOG_JSON` | `true` for machine readable logs |
| `TRUSTED_PROXY_COUNT` | number of trusted proxy hops |
| `TALISMAN_FORCE_HTTPS` | `true` behind TLS termination |

---

## 9. Verifying the deployment

```bash
curl -i https://your-app/health/live     # 200, status "alive"
curl -i https://your-app/health/ready    # 200, status "ready"
```

`/health/ready` returns `503` with `degraded` when the database is
unreachable, which is exactly what an orchestrator needs to decide whether to
route traffic to the instance.

Open the dashboard and submit the registration form twice with the same email
address: the second attempt must be rejected with HTTP 409. That confirms the
unique index is in place.

---

## 10. Rotating the encryption key

1. Add the new key to `AES_KEYS` and set `ACTIVE_KEY_ID` to it
2. Deploy
3. New records use the new key, old records stay readable

```env
AES_KEYS=v1:OLD_KEY,v2:NEW_KEY
ACTIVE_KEY_ID=v2
```

Remove the old key only after every stored record has been re-encrypted.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `/health/ready` returns 503 | The database is unreachable | Check `MONGO_URI` and the Atlas network access list |
| Registration returns 403 | The capability code does not match | Check `CAPABILITY_CODES`, the code is trimmed before comparison |
| Registration returns 500 "not configured" | No AES key is present | Set `AES_KEYS` or `AES_KEY` |
| The dashboard is empty | The database name does not match | Check `DATABASE_NAME` |
| Redirects to HTTPS in local development | Talisman forces HTTPS | Set `TALISMAN_FORCE_HTTPS=false` |
| HTTP 429 | The rate limit was reached | Raise `RATELIMIT_REGISTRATION` or wait |
