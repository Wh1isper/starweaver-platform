XTASK = cargo run -p xtask --locked --
GATEWAY_IMAGE ?= starweaver-gateway:dev
GATEWAY_DOCKER_PLATFORM ?= linux/amd64
DOCKER_COMPOSE ?= docker compose
GATEWAY_COMPOSE_PROJECT ?= starweaver-platform
GATEWAY_SMOKE_PORT ?= 18080

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

.PHONY: docker-build
docker-build: docker-build-gateway ## Build service Docker images

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

.PHONY: docs-check
docs-check: ## Validate documentation structure
	@echo "Checking docs"
	@$(XTASK) check-docs-examples

.PHONY: docs-build
docs-build: ## Build the static documentation site
	@echo "Building docs site"
	@mdbook build
	@$(XTASK) finalize-docs-site

.PHONY: scripts-check
scripts-check: ## Validate repository automation scripts through xtask
	@echo "Checking repository scripts"
	@$(XTASK) check-repository-scripts

.PHONY: lint
lint: docs-check ## Run pre-commit hooks and docs checks across the repository
	@echo "Running pre-commit"
	@pre-commit run -a

.PHONY: ci
ci: fmt-check check test scripts-check docs-check docs-build ## Run the same core checks as CI
