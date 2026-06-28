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
External login providers are created through the admin identity-provider API.
Generic OIDC is the standard external login provider and can use issuer
discovery or explicit authorization, token, and JWKS endpoints. GitHub OAuth App
remains a separate convenience provider kind for operators that want GitHub
login without an OIDC broker.
Compose also mounts `gateway-export-objects` at `/data/gateway-exports` and
sets `STARWEAVER_GATEWAY_EXPORT_OBJECT_STORAGE_DIR` to that path by default for
`storage_backend: file_object_storage` export jobs.

Production profiles fail closed unless the deployment declares the browser
security boundary explicitly. Set `STARWEAVER_GATEWAY_PUBLIC_BASE_URL` to the
HTTPS gateway URL, set `STARWEAVER_GATEWAY_CORS_ALLOWED_ORIGINS` to a
comma-separated list of HTTPS origins, and require secure session cookies with:

```bash
STARWEAVER_GATEWAY_SESSION_COOKIE_SECURE=true
STARWEAVER_GATEWAY_SESSION_COOKIE_HTTP_ONLY=true
STARWEAVER_GATEWAY_SESSION_COOKIE_SAME_SITE=lax
```

The HTTP service currently uses the foundation in-memory runtime store. In
`prod` or `production`, startup rejects that profile instead of silently serving
non-durable state. Wire the PostgreSQL-backed runtime repository before
enabling production traffic.

## Gateway Fake-Provider Load And Soak Harnesses

The repository includes deterministic load and soak harnesses that run against
the in-process fake provider replay path. They require no live provider secrets,
PostgreSQL, Redis, or network egress:

```bash
make gateway-load-harness
make gateway-soak-harness
```

`make ci` runs both harnesses with small defaults. Increase the local load shape
with:

```bash
GATEWAY_LOAD_ITERATIONS=1000 GATEWAY_LOAD_CONCURRENCY=8 make gateway-load-harness
GATEWAY_SOAK_SECONDS=60 GATEWAY_SOAK_CONCURRENCY=8 make gateway-soak-harness
```

The harnesses replay every foundation protocol family, including streaming and
provider-native denial, through the shared route authorization path and fake
provider response builder. They fail if a replay case skips authorization,
returns the wrong protocol family, changes streaming behavior, or grants
provider-native access without an explicit production design.

## Gateway Backup And Restore

Backups must preserve PostgreSQL rows, object-storage exports, external secret
backend material, and release metadata as one recovery point. Do not restore a
database snapshot without confirming the matching secret backend and object
storage generation are available.

Minimum backup set:

- PostgreSQL physical or logical backup for gateway metadata, usage, audit,
  config snapshots, notification state, export manifests, and migration history.
- Object storage generation for usage and audit export objects referenced by
  export manifests.
- Secret backend snapshot or provider-managed recovery point for every active
  `secret_ref_id`.
- Release artifact metadata: image digest, migration versions, config snapshot
  version, and runbook revision.

Restore order:

1. Stop gateway writers and notification/export workers.

2. Restore PostgreSQL to the selected recovery point.

3. Restore or reattach the secret backend generation that contains every active
   secret ref used by provider credentials, webhook signing, OTel headers, and
   login providers.

4. Restore object storage objects referenced by export manifests whose retention
   window has not expired.

5. Start the migration check command:

   ```bash
   starweaver-gateway migrate check
   ```

6. Start one gateway in live readiness mode and verify `/readyz` reports applied
   migrations, Redis-compatible connectivity, and latest published config
   version.

7. Re-enable workers and verify audit event counts, usage event counts, ledger
   aggregates, export manifests, and secret ref fingerprints against the backup
   manifest.

The local deterministic rehearsal is:

```bash
make gateway-restore-rehearsal
```

The rehearsal creates config snapshot, secret ref, audit, usage, and ledger
evidence in one in-memory store, restores them into a fresh store, and verifies
that config checksums, secret metadata plus backend values, audit evidence,
usage events, and rebuilt ledger aggregates remain consistent. It also checks
that audit evidence does not contain raw secret material. `make ci` runs this
rehearsal with no external services.

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

## Gateway Export Objects

Export jobs support three v1 storage choices:

- `inline_manifest` keeps the redacted export rows inside the manifest and is
  the default for small local exports.
- `file_object_storage` writes the redacted export payload to the absolute
  directory configured by `STARWEAVER_GATEWAY_EXPORT_OBJECT_STORAGE_DIR`.
- `object_storage` writes the redacted export payload to the HTTPS base URL
  configured by `STARWEAVER_GATEWAY_EXPORT_OBJECT_STORAGE_URL` with an HTTP
  `PUT` request. `STARWEAVER_GATEWAY_EXPORT_OBJECT_STORAGE_AUTHORIZATION` can
  set an optional `Authorization` header, and
  `STARWEAVER_GATEWAY_EXPORT_OBJECT_STORAGE_TIMEOUT_SECONDS` controls the
  bounded request timeout.

The file backend writes objects under:

```text
${STARWEAVER_GATEWAY_EXPORT_OBJECT_STORAGE_DIR}/{tenant_id}/{export_job_id}.json
```

The external object storage backend sends:

```text
PUT ${STARWEAVER_GATEWAY_EXPORT_OBJECT_STORAGE_URL}/{tenant_id}/{export_job_id}.json
```

The configured URL must use HTTPS in production; loopback HTTP is accepted only
for local and test profiles. API responses return logical
`file-object://gateway-exports/...` or `object-storage://gateway-exports/...`
references, checksum, byte count, and manifest metadata. They do not expose the
local root path, external base URL, authorization header, or inline exported
rows for object-backed exports. Export payloads follow the webhook/export
redaction policy and must not contain raw request bodies, provider bodies,
upstream credentials, API key values, or secret material. If an object writer is
missing, unsafe, or fails, the job fails closed with a redacted failure manifest
instead of reporting a false success.

## Gateway Incident Runbooks

All incident actions should start with a strong-auth operator session, a short
incident id, and a UTC expiry for temporary emergency operations. Do not use API
keys for emergency actions. Capture `/readyz`, `/admin/v1/realtime/overview`,
the relevant usage or dashboard view, and `/admin/v1/emergency/operations`
before and after the change.

Use this request shape for versioned emergency actions:

```json
{
  "idempotency_key": "incident-2026-06-26-example",
  "expected_version": 1,
  "reason": "Short operator-visible reason.",
  "expires_at": "2026-06-26T09:00:00Z"
}
```

### Upstream Credential Leak

1. Identify the affected upstream credential id and current resource version
   from the credential admin view or audit trail.

2. Disable the credential immediately:

   ```text
   POST /admin/v1/emergency/upstream-credentials/{upstream_credential_id}/disable
   ```

3. Rotate or revoke the upstream secret in the external secret manager.

4. Replace the credential through the normal admin API, publish a new config
   snapshot if routing material changed, and keep the emergency disable active
   until replacement traffic is verified.

5. Export the audit and usage window, then notify affected organization or
   project owners.

### Provider Outage

Prefer draining over hard disable when another target can carry traffic.

1. Check `/admin/v1/realtime/overview` and provider endpoint observability for
   stale health, drain state, and error concentration.

2. Drain the routing group when only one traffic lane is affected:

   ```text
   POST /admin/v1/emergency/routing-groups/{routing_group_id}/drain
   ```

3. Disable the provider endpoint when the provider or endpoint is unsafe for all
   routes:

   ```text
   POST /admin/v1/emergency/provider-endpoints/{provider_endpoint_id}/disable
   ```

4. Monitor route decisions, route attempts, and provider endpoint usage until no
   new traffic selects the drained or disabled target.

5. Restore through normal configuration, then let the emergency operation expire
   or replace it with a shorter expiry.

### Runaway Spend

1. Use `/admin/v1/usage/summary`, `/admin/v1/usage/timeseries`, and
   `/admin/v1/usage/breakdown/by-project` to find the narrowest budget scope.

2. Create or identify the budget policy that represents that scope.

3. Force a temporary runtime block:

   ```text
   POST /admin/v1/emergency/budget-policies/{budget_policy_id}/force-block
   ```

4. Inspect project-member and API-key dashboards to identify the caller.

5. Export the usage window and send a budget notification through the configured
   notification sink. Replace the emergency block with a normal budget or quota
   policy before expiry.

### Failed Migration

1. Stop the rollout before starting new gateway instances.

2. Run:

   ```bash
   starweaver-gateway migrate check
   ```

3. Compare the migration state with the release artifact that introduced the
   failure.

4. If data changed, restore from the database backup for that release window or
   apply a reviewed forward repair migration. Do not hand-edit migration rows.

5. Re-run `starweaver-gateway migrate check`, then `/readyz` with live
   dependency probes before reopening traffic.

### OpenTelemetry Exporter Outage

1. Check `/readyz` and `/admin/v1/realtime/overview` for `otel_exporter` health,
   dropped metric count, and failing export configs.

2. Inspect the collector or network path outside the gateway.

3. If the exporter is causing repeated drops or noisy alerts, disable the config:

   ```text
   POST /admin/v1/observability/otel-export/configs/{otel_export_config_id}/disable
   ```

   with body:

   ```json
   {
     "expected_version": 1,
     "reason": "Collector outage under incident review."
   }
   ```

4. Keep model traffic running; exporter failures are evidence and monitoring
   failures, not runtime model-request failures.

5. Re-enable through normal config update after the collector is healthy.

### Redis-Compatible Hot-State Outage

1. Check `/readyz` with live dependency probes. A production profile should
   report hot-state readiness failure when the Redis-compatible backend is
   unreachable.
2. Treat runtime budget and quota behavior according to each policy failure
   mode: hard budget hot-state loss fails closed, quota policies can fail open,
   fail closed, or consume a bounded fail-limited allowance.
3. Keep PostgreSQL as the source of truth. Do not repair counters by direct
   Redis edits.
4. Restore the hot-state backend, then run the runtime policy reconciler path or
   restart the worker role so counters and leases converge from durable usage.
5. Confirm `/admin/v1/realtime/overview` no longer reports conservative budget
   mode or stale worker convergence.

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
- incident runbooks

Future gates:

- OpenAPI schema check
- image SBOM generation
- release artifact checksum generation
