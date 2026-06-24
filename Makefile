XTASK = cargo run -p xtask --locked --

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
