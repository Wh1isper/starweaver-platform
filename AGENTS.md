# Repository Guidelines

## Repository Overview

`starweaver-platform` is the enterprise service workspace for Starweaver. It is
separate from the core `starweaver` SDK/runtime repository.

Current workspace members:

- `crates/starweaver-platform` - agent control-plane crate for hosted
  conversations, runs, sessions, approvals, evidence archives, and environment
  attachments.
- `crates/starweaver-gateway` - LLM gateway crate for model egress, provider
  routing, credentials, budget policy, usage, audit, and observability.
- `xtask` - repository automation used by Makefile targets and CI.

## Boundary Rules

- Keep core runtime, local CLI, provider adapters, tool bundles, envd, and local
  host protocol work in the `starweaver` repository.
- Keep service-side HTTP APIs, tenancy, credentials, audit, policy, migrations,
  deployment, and enterprise operations in this repository.
- The gateway must not depend on the agent runtime.
- The platform service may call the gateway through a versioned HTTP contract,
  but it must not import gateway internals.
- Share stable contracts only after the boundary is clear. Do not introduce
  shared crates for convenience before the second concrete use.

## Documentation Workflow

Use `docs/` for user-facing guides and the mdBook site. Use `spec/` for design
decisions, service boundaries, and architecture notes.

Documentation maintenance rules:

- Keep examples concise, complete, and runnable.
- Put Rust examples in fenced `rust` blocks only when they are intended to be
  checked.
- Prefer mermaid diagrams for architecture flows.
- Update `docs/SUMMARY.md` and `docs/nav.json` when adding, removing, or
  renaming docs pages.
- Keep `docs/` user-facing and keep architecture decisions in `spec/`.

## Development Workflow

After changing code, run:

```bash
make fmt-check
make check
make test
```

After changing docs or mdBook structure, run:

```bash
make docs-check
make docs-build
```

For full local validation, run:

```bash
make ci
```

For repository-wide hooks, run:

```bash
make lint
```

## Coding Conventions

- Use English for code, documentation, commit messages, and file names.
- Keep workspace metadata consistent across `Cargo.toml`, crate manifests,
  `Makefile`, `.pre-commit-config.yaml`, and `.github/workflows/*.yml`.
- Keep early abstractions minimal and add service concepts as concrete needs
  emerge.
- Do not add service framework, database, queue, or cloud dependencies until the
  owning service boundary and validation path are explicit.
