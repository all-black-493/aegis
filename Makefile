SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

UV ?= uv
ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ENVTOOL = $(UV) run --project $(ROOT) --locked python -m aegis.config.envtool

.PHONY: help setup env-file env-upgrade doctor up up-local-ai model-pull openshell-init \
	openshell-image migrate \
	api worker down test test-integration test-security test-local-ai test-openshell lint format \
	typecheck check require-uv require-env

help: ## Show available targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-18s %s\n", $$1, $$2}'

setup: require-uv ## Install locked dependencies and create .env if it does not exist
	$(UV) sync --locked
	@$(MAKE) --no-print-directory env-file

# Internal; called by setup. Never overwrites an existing .env.
env-file: require-uv
	@$(ENVTOOL) create

env-upgrade: require-uv ## Add variables missing from .env (existing values are never changed)
	@$(ENVTOOL) upgrade

doctor: require-uv ## Diagnose the local development environment
	@$(UV) run --locked python -m aegis.doctor

up: require-env ## Start PostgreSQL and wait until it is healthy
	docker compose up --detach --wait

up-local-ai: require-env ## Start PostgreSQL and the local Ollama server (127.0.0.1 only)
	docker compose --profile local-ai up --detach --wait

model-pull: require-uv require-env ## Download AEGIS_OLLAMA_MODEL into the local Ollama server
	$(UV) run --locked --env-file .env aegis model pull

openshell-init: require-uv require-env ## Create AEGIS's OpenShell workspace and check the runtime (needs OpenShell 0.1.7)
	$(UV) run --locked --env-file .env aegis openshell init

openshell-image: ## Build the OpenShell probe image offline from the local ubuntu:24.04 and print its ID
	docker build --pull=false --network none --quiet --tag aegis-openshell-probe:3 deploy/openshell/probe >/dev/null
	@echo "AEGIS_OPENSHELL_IMAGE=$$(docker image inspect --format '{{.Id}}' aegis-openshell-probe:3)"

migrate: require-uv require-env ## Create or update database roles, then apply migrations
	$(UV) run --locked --env-file .env aegis db bootstrap
	$(UV) run --locked --env-file .env aegis db migrate

api: require-uv require-env ## Run the API on 127.0.0.1 (port AEGIS_API_PORT, default 8000)
	$(UV) run --locked --env-file .env python -m aegis.apps.api

worker: require-uv require-env ## Run the task worker
	$(UV) run --locked --env-file .env python -m aegis.apps.worker

down: require-env ## Stop all services, including local AI (volumes are kept)
	docker compose --profile '*' down

test: require-uv ## Run unit tests (no Docker, database, models or credentials needed)
	$(UV) run --locked pytest tests/unit

test-integration: require-uv require-env ## Run integration and end-to-end tests (requires `make up`)
	$(UV) run --locked --env-file .env pytest -m 'not local_ai and not openshell' tests/integration tests/e2e

test-security: require-uv require-env ## Run the security suite (requires `make up`)
	$(UV) run --locked --env-file .env pytest tests/security

test-local-ai: require-uv require-env ## Run tests against the local Ollama model (requires `make up-local-ai` and `make model-pull`)
	$(UV) run --locked --env-file .env pytest -m local_ai tests/integration tests/e2e

test-openshell: require-uv require-env ## Run tests against the real OpenShell gateway (requires `make openshell-init`)
	$(UV) run --locked --env-file .env pytest -m openshell tests/integration tests/e2e

lint: require-uv ## Check formatting and lint with Ruff
	$(UV) run --locked ruff format --check .
	$(UV) run --locked ruff check .

format: require-uv ## Sort imports and format code with Ruff
	$(UV) run --locked ruff check --select I --fix .
	$(UV) run --locked ruff format .

typecheck: require-uv ## Type-check with mypy (strict)
	$(UV) run --locked mypy

check: lint typecheck ## Run all static checks

require-uv:
	@command -v $(UV) >/dev/null 2>&1 || { \
		echo "error: uv was not found on PATH. See docs/development/getting-started.md." >&2; \
		exit 1; }

require-env:
	@[ -f .env ] || { echo "error: .env not found; run make setup" >&2; exit 1; }
