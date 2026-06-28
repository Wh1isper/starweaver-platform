# Testing

The repository follows the same quality-gate shape as the core Starweaver
workspace, trimmed to the current platform and gateway crates.

Local validation:

```bash
make fmt-check
make check
make test
make scripts-check
make docs-check
make docs-build
```

Service smoke checks:

```bash
make docker-build
make compose-smoke
```

GitHub Actions runs:

- Rust formatting.
- Workspace check and clippy.
- Linux tests.
- Repository automation checks.
- Gateway image build and `/readyz` smoke when container inputs change.
- Pre-commit hooks.
- mdBook build and Cloudflare Pages deploy on `main`.

Future service-specific gates include OpenAPI validation, SBOM generation, and
release artifact checksum generation.
