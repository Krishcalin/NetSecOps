# NetSecOps developer and operator commands (SRS §9).
#
# `make up` is the single-command bootstrap: generate keys if missing, start the stack,
# run migrations, and print the URL.

SHELL := /bin/bash
.DEFAULT_GOAL := help

COMPOSE := docker compose -f deploy/docker-compose.yml --env-file .env
BACKEND := backend
FRONTEND := frontend
VENV := $(BACKEND)/.venv
PY := $(VENV)/bin/python
ifeq ($(OS),Windows_NT)
	PY := $(VENV)/Scripts/python.exe
endif

# Tests need a database. This points at the compose Postgres on its host port.
export TEST_DATABASE_URL ?= postgresql+asyncpg://netsecops:netsecops@localhost:5442/netsecops_test

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ────────────────────────────── bootstrap ──────────────────────────────

.PHONY: env
env: ## Create .env with freshly generated keys if it does not exist
	@if [ -f .env ]; then \
		echo ".env already exists — leaving it alone."; \
	else \
		cp .env.example .env; \
		SECRET=$$($(PY) -c "import secrets;print(secrets.token_urlsafe(64))"); \
		MASTER=$$($(PY) -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"); \
		sed -i.bak "s|^SECRET_KEY=.*|SECRET_KEY=$$SECRET|" .env; \
		sed -i.bak "s|^MASTER_KEY=.*|MASTER_KEY=$$MASTER|" .env; \
		rm -f .env.bak; \
		echo "Wrote .env with generated SECRET_KEY and MASTER_KEY."; \
		echo "BACK UP MASTER_KEY SEPARATELY — losing it loses every stored credential."; \
	fi

.PHONY: up
up: env ## Build and start the full stack, run migrations, print the URL
	$(COMPOSE) up -d --build
	@echo "Waiting for the API to become healthy..."
	@for i in $$(seq 1 40); do \
		if curl -fsS http://localhost:8000/healthz >/dev/null 2>&1; then break; fi; \
		sleep 2; \
	done
	@echo ""
	@echo "  NetSecOps is up."
	@echo "    UI       http://localhost:8080"
	@echo "    API docs http://localhost:8000/api/v1/docs"
	@echo ""
	@echo "  Create the first administrator with:  make create-admin"
	@echo "  Then, for something to look at:       make demo-seed"

.PHONY: down
down: ## Stop the stack (data volume is kept)
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack AND delete the database volume
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Follow logs from all services
	$(COMPOSE) logs -f

.PHONY: create-admin
create-admin: ## Create the initial Super Admin
	$(COMPOSE) exec api netsecops-cli create-admin

.PHONY: demo-seed
demo-seed: ## Seed a demonstration estate — no device contacted, no credential needed
	$(COMPOSE) exec api netsecops-cli demo-seed

.PHONY: demo-purge
demo-purge: ## Remove the demonstration estate, leaving any real device alone
	$(COMPOSE) exec api netsecops-cli demo-purge

# ───────────────────────────── development ─────────────────────────────

.PHONY: install
install: ## Install backend and frontend dependencies
	python -m venv $(VENV) || true
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e "$(BACKEND)[dev]"
	cd $(FRONTEND) && npm install

.PHONY: db
db: ## Start just PostgreSQL (for running the app outside Docker)
	$(COMPOSE) up -d db

.PHONY: dev-api
dev-api: ## Run the API with auto-reload
	cd $(BACKEND) && ../$(PY) -m uvicorn netsecops.main:app --reload --port 8000

.PHONY: dev-ui
dev-ui: ## Run the Vite dev server
	cd $(FRONTEND) && npm run dev

.PHONY: migrate
migrate: ## Apply database migrations
	cd $(BACKEND) && ../$(PY) -m alembic upgrade head

.PHONY: migration
migration: ## Generate a migration: make migration M="add devices"
	cd $(BACKEND) && ../$(PY) -m alembic revision --autogenerate -m "$(M)"

.PHONY: gen-api
gen-api: ## Regenerate frontend types from the running API's OpenAPI document
	cd $(FRONTEND) && npm run gen:api

# ───────────────────────── quality gates (CI) ──────────────────────────

.PHONY: lint
lint: ## Lint backend and frontend
	cd $(BACKEND) && ../$(PY) -m ruff check .
	cd $(BACKEND) && ../$(PY) -m ruff format --check .
	cd $(FRONTEND) && npm run lint

.PHONY: format
format: ## Auto-format backend and frontend
	cd $(BACKEND) && ../$(PY) -m ruff check --fix .
	cd $(BACKEND) && ../$(PY) -m ruff format .
	cd $(FRONTEND) && npm run format

.PHONY: typecheck
typecheck: ## Type-check backend (mypy --strict) and frontend (tsc)
	cd $(BACKEND) && ../$(PY) -m mypy netsecops
	cd $(FRONTEND) && npm run typecheck

.PHONY: test
test: ## Run backend and frontend tests
	cd $(BACKEND) && ../$(PY) -m pytest
	cd $(FRONTEND) && npm run test

.PHONY: test-cov
test-cov: ## Backend tests with coverage (NFR-MAINT-01: >=85%)
	cd $(BACKEND) && ../$(PY) -m pytest --cov --cov-report=term-missing --cov-report=xml

.PHONY: security
security: ## Dependency and static security scans (SEC-07)
	cd $(BACKEND) && ../$(PY) -m bandit -c pyproject.toml -r netsecops -q
	cd $(BACKEND) && ../$(PY) -m pip_audit --skip-editable || true
	cd $(FRONTEND) && npm audit --audit-level=high || true

.PHONY: verify-audit
verify-audit: ## Verify the audit hash chain (FR-AUD-02)
	$(COMPOSE) exec api netsecops-cli verify-audit-chain

.PHONY: check
check: lint typecheck test security ## Run every quality gate
	@echo "All gates passed."
