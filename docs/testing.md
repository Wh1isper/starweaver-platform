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
- Repository automation checks, plus explicit OpenAPI and gateway contract
  steps so contract regressions are visible as named CI failures.
- Release migration checksum manifest checks for embedded gateway and platform
  SQL migrations.
- OpenAPI contract generation checks for gateway and platform route metadata.
- Gateway contract alignment checks for route metadata, replay cases, protocol
  families, authorization action ids, and OpenAPI extensions.
- Gateway fake-provider load, soak, and restore rehearsal harnesses.
- Static docs publish generated OpenAPI JSON contracts under `/openapi/` with
  explicit JSON headers.
- Gateway and platform image build plus `/readyz` smoke when container inputs
  change.
- Nightly and release gateway and platform image publication to GCR with
  BuildKit SBOM and provenance attestations.
- Image metadata artifacts with digest, tags, labels, OpenAPI schemas,
  migration checksums, and `SHA256SUMS`.
- Manual-only live provider smoke workflow for deployed gateways; this is not
  part of ordinary CI and requires `LIVE_GATEWAY_API_KEY`.
- Pre-commit hooks.
- mdBook build and Cloudflare Pages deploy on `main`.

Future service-specific gates include generated client compatibility checks.
