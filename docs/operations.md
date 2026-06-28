# Operations

The first operational layer is repository infrastructure: CI, pre-commit,
mdBook docs, and Cloudflare Pages deployment.

## Gateway Local Stack

The gateway image includes a migration command:

```bash
starweaver-gateway migrate run
starweaver-gateway migrate check
```

Both commands read `STARWEAVER_GATEWAY_DATABASE_URL`.

Use Docker Compose for a local dependency stack with PostgreSQL, Redis, a
one-shot migration container, and the gateway service:

```bash
make compose-up
make compose-migrate
make compose-smoke
make compose-down
```

`make compose-smoke` builds the gateway image, starts the stack on port `18080`,
checks the migration history, probes `/readyz`, and tears the stack down. The
compose gateway uses live readiness probes for PostgreSQL migration status and
Redis-compatible hot-state connectivity.

The compose gateway does not enable login by default and does not auto-create
GitHub OAuth App or OIDC login providers. Set
`STARWEAVER_GATEWAY_SINGLE_USER_USERNAME` and
`STARWEAVER_GATEWAY_SINGLE_USER_PASSWORD` before `make compose-up` when a local
password bootstrap login is needed. Compose also passes through
`STARWEAVER_GATEWAY_SINGLE_USER_EMAIL`,
`STARWEAVER_GATEWAY_SINGLE_USER_DISPLAY_NAME`, and
`STARWEAVER_GATEWAY_SINGLE_USER_SESSION_TTL_SECONDS` when they are set.

Readiness behavior is controlled by:

```text
STARWEAVER_GATEWAY_DEPENDENCY_PROBE_MODE=configured|live
STARWEAVER_GATEWAY_READINESS_PROBE_TIMEOUT_MS=750
```

`configured` reports whether dependency URLs are present without opening
network connections. `live` connects to PostgreSQL, verifies all embedded
migrations are applied, and checks that the Redis-compatible hot-state endpoint
accepts TCP connections. Secret backend and telemetry readiness remain
profile-level checks until backend-specific clients are wired in.

## Docs Deployment

The docs workflow builds `book/` and deploys it to Cloudflare Pages:

```text
project: starweaver-platform-docs
branch: main
output: book
```

Required GitHub secrets:

- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

Required GitHub environment:

- `docs`

## Release Gates

Current gates:

- migration check
- Docker build smoke
- local compose smoke

Future gates:

- OpenAPI schema check
- image SBOM generation
- release artifact checksum generation
