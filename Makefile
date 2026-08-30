COMPOSE_FILE := compose.dev.yaml
COMPOSE := docker compose -f $(COMPOSE_FILE)
WEB_PORT ?= 3000
PSQL := psql --no-psqlrc -v ON_ERROR_STOP=1 -U core_api -d core_api
DEV_CHECK_SCRIPT := scripts/dev/check-stack.mjs

# sync+restart arrived in Compose 2.23.0; 2.22 knows watch but not that action.
MIN_COMPOSE_VERSION := 2.23.0
COMPOSE_VERSION ?= $(shell docker compose version --short 2>/dev/null)

# The ledger must agree with the migrations the repository actually carries.
MIGRATION_FILES := $(wildcard services/core-api/internal/persistence/postgres/migration/sql/*.sql)
EXPECTED_MIGRATIONS := $(words $(MIGRATION_FILES))

.PHONY: help dev-doctor dev dev-up dev-down dev-logs dev-ps dev-check dev-migrate dev-db

help:
	@echo "Local development stack. It needs Docker with Compose, GNU Make and a POSIX"
	@echo "environment providing awk."
	@echo
	@echo "  make dev-doctor   check Docker and a Compose version that supports sync+restart"
	@echo "  make dev          build, start attached and watch for changes"
	@echo "  make dev-up       start detached, building and waiting for health"
	@echo "  make dev-down     stop the stack, keeping the database volume"
	@echo "  make dev-logs     follow the logs"
	@echo "  make dev-ps       show the state of each service"
	@echo "  make dev-check    assert postgres, migrations, readiness, web and the /api rewrite"
	@echo "  make dev-migrate  run the migrations again, from the running sources"
	@echo "  make dev-db       open psql inside postgres"
	@echo
	@echo "  the web application is served on http://localhost:$(WEB_PORT)"

dev-doctor:
	@docker version --format 'docker {{.Server.Version}}' || { echo "docker is not available"; exit 1; }
	@printf '%s %s\n' '$(COMPOSE_VERSION)' '$(MIN_COMPOSE_VERSION)' | awk '{ \
		split($$1, has, "."); split($$2, want, "."); \
		for (i = 1; i <= 3; i++) { \
			x = has[i] + 0; y = want[i] + 0; \
			if (x > y) { print "compose " $$1 " supports sync+restart"; exit 0 } \
			if (x < y) { printf "compose %s is older than %s, which sync+restart requires\n", $$1, $$2 > "/dev/stderr"; exit 1 } \
		} \
		print "compose " $$1 " supports sync+restart"; exit 0 }'
	@$(COMPOSE) config --quiet && echo "$(COMPOSE_FILE) is valid"

dev:
	$(COMPOSE) up --build --watch

dev-up:
	$(COMPOSE) up --build --detach --wait

dev-down:
	$(COMPOSE) down

dev-logs:
	$(COMPOSE) logs --follow

dev-ps:
	$(COMPOSE) ps --all

# Every assertion runs inside a container and fails the target on its own.
dev-check:
	@$(COMPOSE) exec -T postgres pg_isready -U core_api -d core_api
	@$(COMPOSE) exec -T postgres $(PSQL) -Atc \
		"SELECT 'migrations reconciled: ' || (1 / (count(*) = $(EXPECTED_MIGRATIONS) \
		 AND max(version) = $(EXPECTED_MIGRATIONS))::int * $(EXPECTED_MIGRATIONS)) FROM schema_migrations"
	@$(COMPOSE) exec -T web node - < $(DEV_CHECK_SCRIPT)
	@$(COMPOSE) exec -T core-api go run ./cmd/migrate

dev-migrate:
	$(COMPOSE) exec -T core-api go run ./cmd/migrate

dev-db:
	$(COMPOSE) exec postgres psql --no-psqlrc -U core_api -d core_api
