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

GitHub Actions runs:

- Rust formatting.
- Workspace check and clippy.
- Linux, macOS, and Windows tests.
- Repository automation checks.
- Pre-commit hooks.
- mdBook build and Cloudflare Pages deploy on `main`.

Add service-specific gates such as migrations, OpenAPI validation, Docker smoke
tests, and compose smoke tests when those artifacts exist.
