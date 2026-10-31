SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

UV ?= uv

.PHONY: help setup env-file doctor up down test test-integration lint format typecheck check \
	require-uv require-env

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-18s %s\n", $$1, $$2}'

setup: require-uv ## Install locked dependencies and create .env if it does not exist
	$(UV) sync --locked
	@$(MAKE) --no-print-directory env-file

doctor: require-uv ## Diagnose the local development environment
	@$(UV) run --locked python -m aegis.doctor

up: require-env ## Start PostgreSQL and wait until it is healthy
	docker compose up --detach --wait

down: require-env ## Stop services (the database volume is kept)
	docker compose down

test: require-uv ## Run unit tests (no Docker, database, models or credentials needed)
	$(UV) run --locked pytest tests/unit

test-integration: require-uv require-env ## Run integration tests (requires `make up`)
	$(UV) run --locked --env-file .env pytest tests/integration

lint: require-uv ## Check formatting and lint with Ruff
	$(UV) run --locked ruff format --check .
	$(UV) run --locked ruff check .

format: require-uv ## Sort imports and format code with Ruff
	$(UV) run --locked ruff check --select I --fix .
	$(UV) run --locked ruff format .

typecheck: require-uv ## Type-check with mypy (strict)
	$(UV) run --locked mypy

check: lint typecheck ## Run all static checks

# Internal; called by setup. `set -C` makes the write fail rather than overwrite an existing .env.
env-file:
	@if [ -e .env ]; then \
		echo ".env already exists; leaving it unchanged."; \
	else \
		grep -q '^AEGIS_POSTGRES_PASSWORD=__GENERATED_BY_MAKE_SETUP__$$' .env.example \
			|| { echo "error: .env.example is missing the password placeholder" >&2; exit 1; }; \
		password="$$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')"; \
		[ "$${#password}" -eq 48 ] || { echo "error: could not generate a password" >&2; exit 1; }; \
		( set -C; umask 077; \
			sed "s/^AEGIS_POSTGRES_PASSWORD=.*/AEGIS_POSTGRES_PASSWORD=$$password/" .env.example > .env ); \
		echo "Created .env with a generated PostgreSQL password (file mode 600)."; \
	fi

require-uv:
	@command -v $(UV) >/dev/null 2>&1 || { \
		echo "error: uv was not found on PATH. See docs/development/getting-started.md." >&2; \
		exit 1; }

require-env:
	@[ -f .env ] || { echo "error: .env not found; run make setup" >&2; exit 1; }
