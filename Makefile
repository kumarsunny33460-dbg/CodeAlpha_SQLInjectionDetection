# ===================================================================
# SQLShield - developer shortcuts
# ===================================================================

PYTHON ?= python
VENV   ?= venv
BIN     = $(VENV)/Scripts
BIN_POSIX = $(VENV)/bin

ifeq ($(OS),Windows_NT)
PREFIX = $(BIN)/
else
PREFIX = $(BIN_POSIX)/
endif

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "SQLShield - available targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: install
install: ## Install production and development dependencies
	$(PYTHON) -m pip install -r requirements-dev.txt

.PHONY: setup
setup: install docker-up ## Install the dependencies and start the Docker stack
	@echo ""
	@echo "SQLShield is available at http://127.0.0.1:8000/"

.PHONY: venv
venv: ## Create the virtual environment
	$(PYTHON) -m venv $(VENV)

.PHONY: run
run: ## Start the development server
	$(PREFIX)flask --app app run --debug --port 5000

.PHONY: serve
serve: ## Start the production server locally
	$(PREFIX)gunicorn --config deploy/gunicorn.conf.py wsgi:application

.PHONY: test
test: ## Run the test suite
	$(PREFIX)pytest

.PHONY: coverage
coverage: ## Run the test suite with a coverage report
	$(PREFIX)pytest --cov=sqlshield --cov-report=term-missing --cov-report=html

.PHONY: lint
lint: ## Run the linter
	$(PREFIX)ruff check .

.PHONY: format
format: ## Format the code
	$(PREFIX)ruff format .

.PHONY: lint-fix
lint-fix: ## Fix the lint findings that can be fixed automatically
	$(PREFIX)ruff check --fix .

.PHONY: typecheck
typecheck: ## Run the static type checker
	$(PREFIX)mypy sqlshield

.PHONY: check
check: lint typecheck test ## Run every quality gate

.PHONY: docker-build
docker-build: ## Build the production image
	docker build -t sqlshield:latest .

.PHONY: docker-up
docker-up: ## Start the stack locally with Docker
	docker compose up --build -d

.PHONY: docker-down
docker-down: ## Stop the local Docker stack
	docker compose down -v

.PHONY: clean
clean: ## Remove caches and build artefacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
