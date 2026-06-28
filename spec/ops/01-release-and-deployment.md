# Release And Deployment

Status: discussion draft.

This spec defines the release strategy for a repository that contains both the
LLM gateway and agent platform service.

## Release Unit

Use one Git release tag for the repository:

```text
v0.1.0
```

The tag represents a compatible set of:

- service binaries
- Docker images
- database migrations
- OpenAPI schemas
- deployment manifests
- admin contracts
- client contracts when published

## Artifacts

Each release should publish service images:

```text
ghcr.io/$IMAGE_NAMESPACE/starweaver-gateway:v0.1.0
ghcr.io/$IMAGE_NAMESPACE/starweaver-platform:v0.1.0
starweaver-admin-api:v0.1.0
```

The admin API can be a separate image or part of each service. The release
process should not require that decision before the service boundary is stable.

Release assets should include:

- OpenAPI schemas
- migration checksums
- SBOM files
- container image digests
- Helm chart package when available
- release notes

## Crate Publication

Do not publish internal service crates at the beginning.

Publish crates only when an external user needs stable client or contract APIs.
Candidate crates:

- `starweaver-service-core`
- `starweaver-gateway-client`
- `starweaver-platform-client`

Internal service crates should remain repository artifacts unless there is a
clear external contract.

## Pull Request Gates

Every pull request should run:

```text
cargo fmt --check
cargo check --workspace --locked
cargo test --workspace --locked
embedded migration checksum check
OpenAPI schema check
Docker build smoke
local compose smoke when service files change
```

The exact commands can be added after the workspace and tooling exist.

Current container gate:

- `.github/workflows/images.yml` builds gateway and platform images on pull
  requests that touch Rust service code, Dockerfiles, or the image workflow.
- The smoke build targets Linux `amd64` because the service deployment target
  is Linux-only.

Current contract gate:

- `make migration-checksum-check` verifies `release/migration-checksums.txt`
  against the embedded gateway and platform SQL migration files.
- `make openapi-check` verifies generated gateway and platform OpenAPI contract
  artifacts under `docs/openapi/` match the route metadata compiled into the
  service crates.
- `make gateway-contract-check` verifies gateway route metadata, replay
  contracts, protocol-family coverage, authorization action ids, and generated
  OpenAPI extensions. GitHub Actions runs both checks as named steps, in
  addition to repository automation checks.

## Image Publication

Gateway and platform image publication pushes to GitHub Container Registry
with the workflow-scoped `GITHUB_TOKEN`.

Optional GitHub configuration:

| Name              | Kind     | Purpose                                                  |
| ----------------- | -------- | -------------------------------------------------------- |
| `IMAGE_REGISTRY`  | variable | optional registry host, defaults to `ghcr.io`            |
| `IMAGE_NAMESPACE` | variable | optional package namespace, defaults to repository owner |

Nightly builds are published from `main` by the scheduled workflow and by
`main` branch pushes:

```text
ghcr.io/$IMAGE_NAMESPACE/starweaver-gateway:nightly
ghcr.io/$IMAGE_NAMESPACE/starweaver-gateway:nightly-YYYYMMDD-SHORTSHA
ghcr.io/$IMAGE_NAMESPACE/starweaver-gateway:main-SHORTSHA
ghcr.io/$IMAGE_NAMESPACE/starweaver-platform:nightly
ghcr.io/$IMAGE_NAMESPACE/starweaver-platform:nightly-YYYYMMDD-SHORTSHA
ghcr.io/$IMAGE_NAMESPACE/starweaver-platform:main-SHORTSHA
```

Release builds are published from `v*.*.*` tags or GitHub release publish
events:

```text
ghcr.io/$IMAGE_NAMESPACE/starweaver-gateway:v0.1.0
ghcr.io/$IMAGE_NAMESPACE/starweaver-gateway:0.1.0
ghcr.io/$IMAGE_NAMESPACE/starweaver-gateway:latest
ghcr.io/$IMAGE_NAMESPACE/starweaver-platform:v0.1.0
ghcr.io/$IMAGE_NAMESPACE/starweaver-platform:0.1.0
ghcr.io/$IMAGE_NAMESPACE/starweaver-platform:latest
```

Manual dispatch supports `nightly` and `release` channels. Manual release
dispatch requires a tag such as `v0.1.0`.

Nightly and release image artifact bundles include the pushed image digest,
published tags, OCI labels, the generated OpenAPI schemas from `docs/openapi/`,
the generated migration checksum manifest from `release/migration-checksums.txt`,
and `SHA256SUMS` covering the full artifact tree.

## Release Flow

Recommended flow:

```mermaid
flowchart TD
    pr[Release PR]
    version[Bump workspace version]
    changelog[Update changelog]
    ci[Run full CI]
    tag[Create Git tag]
    images[Build and push images]
    schemas[Upload schemas and checksums]
    helm[Publish Helm chart]
    notes[Publish GitHub Release notes]

    pr --> version
    version --> changelog
    changelog --> ci
    ci --> tag
    tag --> images
    tag --> schemas
    tag --> helm
    images --> notes
    schemas --> notes
    helm --> notes
```

## Migration Policy

Database migrations are part of the release contract.

Rules:

- Migrations must be forward-only.
- Gateway and platform migrations can live in separate directories.
- Shared tables must be owned by shared service specs.
- Every release records migration checksums.
- Rollback means deploying a new forward migration, not editing old migrations.

Candidate layout:

```text
migrations/
  shared/
  gateway/
  platform/
```

## Deployment Modes

Initial deployment modes:

| Mode          | Purpose                                                        |
| ------------- | -------------------------------------------------------------- |
| Local compose | Development and integration smoke tests                        |
| Single-node   | Small self-hosted deployment                                   |
| Multi-node    | Production gateway and platform services behind load balancers |

The gateway and platform service should be independently scalable. Shared
PostgreSQL, Redis, and object storage can be deployed by the operator.

## Version Compatibility

Gateway and platform service images from the same Git release should be
compatible by default. Cross-version compatibility can be introduced later by
versioning the service-to-service HTTP contracts and OpenAPI schemas.

Until those contracts are stable, deploy both services from the same release.
