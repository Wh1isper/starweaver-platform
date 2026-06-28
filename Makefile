XTASK = cargo run -p xtask --locked --
GATEWAY_IMAGE ?= starweaver-gateway:dev
PLATFORM_IMAGE ?= starweaver-platform:dev
GATEWAY_DOCKER_PLATFORM ?= linux/amd64
DOCKER_COMPOSE ?= docker compose
GATEWAY_COMPOSE_PROJECT ?= starweaver-platform
GATEWAY_SMOKE_PORT ?= 18080
GATEWAY_LOAD_ITERATIONS ?= 36
GATEWAY_LOAD_CONCURRENCY ?= 4
GATEWAY_SOAK_SECONDS ?= 1
GATEWAY_SOAK_CONCURRENCY ?= 2
GATEWAY_SOAK_INTERVAL_MS ?= 25

.PHONY: help
help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"; printf "Available commands:\n"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  %-24s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: install
install: ## Install repository developer hooks
	@echo "Installing pre-commit hooks"
	@pre-commit install

.PHONY: fmt
fmt: ## Format Rust code
	@echo "Formatting Rust workspace"
	@cargo fmt --all

.PHONY: fmt-check
fmt-check: ## Check Rust formatting
	@echo "Checking Rust formatting"
	@cargo fmt --all -- --check

.PHONY: clippy
clippy: ## Run clippy for all targets and features
	@echo "Running clippy"
	@cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

.PHONY: check
check: ## Run repository quality checks
	@echo "Checking Rust workspace"
	@cargo check --workspace --all-targets --all-features --locked
	@echo "Running clippy"
	@cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

.PHONY: test
test: ## Run workspace tests
	@echo "Running Rust tests"
	@cargo test --workspace --all-targets --all-features --locked

.PHONY: build
build: ## Build the workspace
	@echo "Building Rust workspace"
	@cargo build --workspace --all-targets --all-features --locked

.PHONY: docker-build-gateway
docker-build-gateway: ## Build the gateway Docker image
	@echo "Building gateway Docker image $(GATEWAY_IMAGE)"
	@docker build \
		--platform $(GATEWAY_DOCKER_PLATFORM) \
		--file crates/starweaver-gateway/Dockerfile \
		--tag $(GATEWAY_IMAGE) \
		.

.PHONY: docker-build-platform
docker-build-platform: ## Build the platform Docker image
	@echo "Building platform Docker image $(PLATFORM_IMAGE)"
	@docker build \
		--platform $(GATEWAY_DOCKER_PLATFORM) \
		--file crates/starweaver-platform/Dockerfile \
		--tag $(PLATFORM_IMAGE) \
		.

.PHONY: docker-build
docker-build: docker-build-gateway docker-build-platform ## Build service Docker images

.PHONY: compose-up
compose-up: ## Start local gateway dependencies and service through Docker Compose
	@$(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT) up --build -d postgres redis gateway-migrate gateway

.PHONY: compose-down
compose-down: ## Stop local gateway Docker Compose services and remove volumes
	@$(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT) down -v

.PHONY: compose-migrate
compose-migrate: ## Run gateway database migrations through Docker Compose
	@$(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT) run --rm gateway-migrate

.PHONY: compose-smoke
compose-smoke: ## Build and run the gateway compose stack, then probe /readyz
	@set -e; \
	export STARWEAVER_GATEWAY_HTTP_PORT=$(GATEWAY_SMOKE_PORT); \
	trap 'STARWEAVER_GATEWAY_HTTP_PORT=$(GATEWAY_SMOKE_PORT) $(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT)-smoke down -v' EXIT; \
	$(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT)-smoke up --build -d postgres redis gateway-migrate gateway; \
	$(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT)-smoke run --rm gateway-migrate migrate check; \
	for attempt in $$(seq 1 60); do \
		if curl -fsS http://127.0.0.1:$(GATEWAY_SMOKE_PORT)/readyz; then \
			exit 0; \
		fi; \
		sleep 2; \
	done; \
	$(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT)-smoke ps; \
	$(DOCKER_COMPOSE) -p $(GATEWAY_COMPOSE_PROJECT)-smoke logs gateway gateway-migrate; \
	exit 1

.PHONY: gateway-load-harness
gateway-load-harness: ## Run deterministic fake-provider load harness
	@$(XTASK) gateway-load-harness \
		--iterations $(GATEWAY_LOAD_ITERATIONS) \
		--concurrency $(GATEWAY_LOAD_CONCURRENCY)

.PHONY: gateway-soak-harness
gateway-soak-harness: ## Run deterministic fake-provider soak harness
	@$(XTASK) gateway-soak-harness \
		--duration-seconds $(GATEWAY_SOAK_SECONDS) \
		--concurrency $(GATEWAY_SOAK_CONCURRENCY) \
		--interval-ms $(GATEWAY_SOAK_INTERVAL_MS)

.PHONY: gateway-restore-rehearsal
gateway-restore-rehearsal: ## Run deterministic gateway backup and restore rehearsal
	@$(XTASK) gateway-restore-rehearsal

.PHONY: gateway-harness-check
gateway-harness-check: gateway-load-harness gateway-soak-harness gateway-restore-rehearsal ## Run gateway fake-provider and restore harnesses

.PHONY: docs-check
docs-check: ## Validate documentation structure
	@echo "Checking docs"
	@$(XTASK) check-docs-examples

.PHONY: docs-build
docs-build: ## Build the static documentation site
	@echo "Building docs site"
	@mdbook build
	@$(XTASK) finalize-docs-site

.PHONY: openapi-generate
openapi-generate: ## Generate service OpenAPI contract files from route metadata
	@$(XTASK) generate-openapi

.PHONY: openapi-check
openapi-check: ## Validate generated service OpenAPI contract files
	@$(XTASK) check-openapi

.PHONY: migration-checksum-generate
migration-checksum-generate: ## Generate release migration checksum manifest
	@$(XTASK) generate-migration-checksums

.PHONY: migration-checksum-check
migration-checksum-check: ## Validate release migration checksum manifest
	@$(XTASK) check-migration-checksums

.PHONY: gateway-contract-check
gateway-contract-check: ## Validate gateway route, replay, and OpenAPI contract alignment
	@$(XTASK) check-gateway-contracts

.PHONY: scripts-check
scripts-check: ## Validate repository automation scripts through xtask
	@echo "Checking repository scripts"
	@$(XTASK) check-repository-scripts

.PHONY: lint
lint: docs-check ## Run pre-commit hooks and docs checks across the repository
	@echo "Running pre-commit"
	@pre-commit run -a

.PHONY: ci
ci: fmt-check check test scripts-check migration-checksum-check openapi-check gateway-contract-check gateway-harness-check docs-check docs-build ## Run the same core checks as CI
