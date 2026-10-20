# Contributing

Thanks for taking the time to improve SQLShield. This guide covers the local
workflow, the quality gates and the conventions the codebase follows.

---

## Getting set up

```bash
git clone https://github.com/kumarsunny33460-dbg/CodeAlpha_SQLInjectionDetection.git
cd CodeAlpha_SQLInjectionDetection

python -m venv venv
venv\Scripts\activate          # Windows
source venv/bin/activate       # macOS / Linux

pip install -r requirements-dev.txt
cp .env.example .env
```

Windows users can use the helper script instead:

```powershell
./scripts/dev.ps1 setup
```

The setup command creates the virtual environment, installs the dependencies,
creates `.env` from `.env.example` when it is missing and starts the Docker
stack.

The test suite does not need a database: `mongomock` provides an in-memory
MongoDB.

---

## Daily commands

| Task | Make | PowerShell | Raw |
|------|------|-----------|-----|
| Bootstrap everything | — | `./scripts/dev.ps1 setup` | — |
| Install | `make install` | `./scripts/dev.ps1 install` | `pip install -r requirements-dev.txt` |
| Run | `make run` | `./scripts/dev.ps1 run` | `flask --app app run --debug` |
| Test | `make test` | `./scripts/dev.ps1 test` | `pytest` |
| Lint | `make lint` | `./scripts/dev.ps1 lint` | `ruff check .` |
| Format | `make format` | `./scripts/dev.ps1 format` | `ruff format .` |
| Types | `make typecheck` | — | `mypy sqlshield` |
| All gates | `make check` | `./scripts/dev.ps1 check` | — |
| Docker stack | `make docker-up` | `./scripts/dev.ps1 docker` | `docker compose up --build -d` |

---

## Quality gates

Every pull request runs the following in GitHub Actions:

1. `ruff check .` — linting
2. `ruff format --check .` — formatting
3. `mypy sqlshield` — static typing
4. `pytest --cov=sqlshield` — tests with coverage
5. A Docker build followed by a start-up smoke test

All five must pass before a change is merged.

### Pre-commit

```bash
pip install pre-commit
pre-commit install
```

The hooks run the formatter, the linter, the type checker and a set of
repository hygiene checks such as trailing whitespace and secret detection.

---

## Conventions

### Python

* Target Python 3.12; the code stays compatible with 3.10.
* Every module starts with a docstring that explains **why** it exists.
* Type hints on public functions. `mypy` must stay clean.
* Line length 90 characters, enforced by Ruff.
* No bare `except:` — catch the specific exception and add a `# noqa` with a
  reason when a broad catch is genuinely required.
* Never log secrets, payloads or credentials.

### Frontend

* The interface is a single page application in `templates/index.html`.
* Keep the existing class vocabulary in `static/style.css`.
* Any new endpoint call must go through `/api/v1` and handle the shared
  response envelope.
* Sensitive values are never rendered, not even inside the interactive
  scanner.

### Security

* Detection rules live in `sqlshield/security/rules.py` with a category, a
  weight and the fields they apply to. Keep the weight in step with the
  severity bands documented in `docs/ARCHITECTURE.md`.
* Anything that compares a secret must use a constant time comparison.
* Never store a password in a recoverable form.

---

## Adding a detection rule

1. Add the rule to `RULES` in `sqlshield/security/rules.py`.
2. Give it a category, a weight, a description and the fields it applies to.
3. Add a true positive fixture to `tests/test_detector.py`.
4. Add a false positive fixture if the rule could plausibly match ordinary
   data.
5. Run `pytest tests/test_detector.py`.

---

## Commit messages

Use the imperative mood and keep the subject under 72 characters.

```
Add a rule for stacked query detection
Fix the fingerprint derivation for rotated keys
Document the deployment workflow for Render
```

---

## Reporting a security issue

Please do not open a public issue for a vulnerability. Email the maintainer
directly so a fix can be prepared before the details are published.

---

## Pull requests

1. Create a branch: `git checkout -b feature/short-description`
2. Make the change and add tests for it
3. Run `make check`
4. Commit with a clear message
5. Open the pull request and describe **what** changed and **why**
