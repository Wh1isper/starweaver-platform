# Security, Observability, And Operations

Status: design draft for review.

This spec defines the operational baseline for the gateway. It covers
secret handling, redaction, audit evidence, telemetry, storage, deployment,
backup, incident response, and operational readiness.

The gateway is a high-value egress control point. A deployment can continue
without a web UI, but it cannot be considered enterprise-ready without clear
security and operations behavior.

## Goals

- Protect inbound API keys, caller credentials, upstream credentials, login
  provider secrets, OAuth tokens, and sensitive model payloads.
- Produce enough observability to debug routing, usage, provider health, and
  policy decisions.
- Keep audit evidence durable and redacted.
- Support predictable deployment and upgrade behavior.
- Define failure modes before implementation adds service dependencies.
- Keep the open-source gateway usable without a large vendor platform.

## Non-Goals

- Do not design a full SIEM product.
- Do not store raw prompts or raw completions by default.
- Do not implement payment compliance or tax reporting.
- Do not require Kubernetes for local or small production deployments.
- Do not rely on a future UI for operational safety.

## Security Boundary

The gateway protects four trust boundaries:

| Boundary             | Protected Material                                         |
| -------------------- | ---------------------------------------------------------- |
| inbound client       | API keys, caller credentials, scopes, tenant context       |
| admin control plane  | configuration, secret references, audit events             |
| upstream provider    | provider API keys, OAuth tokens, provider account metadata |
| observability/export | traces, logs, usage events, notifications, debug payloads  |

Runtime workers should treat all model request bodies and provider responses as
sensitive even when a deployment marks the data as non-PII.

## Credential Types

Credential classes:

| Credential                   | Direction                 | Storage                              |
| ---------------------------- | ------------------------- | ------------------------------------ |
| API key                      | caller to gateway         | hash only                            |
| login session cookie         | browser to gateway        | opaque token hash in session store   |
| login provider client secret | gateway to login provider | secret backend                       |
| upstream API key             | gateway to provider       | secret backend                       |
| Codex OAuth token            | gateway to Codex provider | secret backend with refresh metadata |
| webhook signing secret       | gateway to external sink  | secret backend                       |
| admin service token          | admin caller to gateway   | deployment identity provider or hash |

The config database stores references, metadata, hashes, and key prefixes. It
does not store raw secret values unless the deployment explicitly uses an
embedded development secret backend.

## Secret Backends

Backend classes:

| Backend                | Use                          | Current startup support                        |
| ---------------------- | ---------------------------- | ---------------------------------------------- |
| `memory`               | tests only                   | accepted outside production                    |
| `file`                 | self-hosted deployments      | accepted; production requires an explicit root |
| `database_encrypted`   | small self-hosted deployment | planned; rejected until backend is implemented |
| `cloud_secret_manager` | managed production           | planned; rejected until backend is implemented |
| `external_vault`       | enterprise deployment        | planned; rejected until backend is implemented |

The API should expose a `SecretRef` abstraction so provider credentials can move
between backends without changing routing resources.

## SecretRef

Secret reference fields:

| Field           | Meaning                                                           |
| --------------- | ----------------------------------------------------------------- |
| `secret_ref_id` | stable gateway id for the secret reference                        |
| `locator_mask`  | redacted backend locator or display mask                          |
| `backend`       | configured secret backend                                         |
| `scope_kind`    | tenant, organization, system                                      |
| `scope_id`      | owning scope                                                      |
| `purpose`       | upstream credential, login provider, webhook signing, OAuth token |
| `version`       | backend version if available                                      |
| `created_at`    | creation time                                                     |
| `rotated_at`    | last rotation time                                                |
| `expires_at`    | optional expiry                                                   |
| `fingerprint`   | non-secret digest for audit                                       |

`SecretRef` values should be treated as sensitive metadata. They are safer than
raw secrets, but they can still reveal provider or tenant structure. Default
read APIs return only `secret_ref_id`, purpose, version, fingerprint, mask,
backend class, and timestamps. They must not return raw backend locators,
backend paths, auth headers, or embedded secret material.

Raw backend locators are available only through a strong-auth `security_admin`
path for break-glass diagnostics. Audit diffs record only version,
fingerprint, purpose, and masked locator changes.

## Secret Rotation

Rotation flow:

```mermaid
sequenceDiagram
    participant Admin
    participant API
    participant SecretStore
    participant Config
    participant Runtime
    participant Provider

    Admin->>API: write new secret value
    API->>SecretStore: store secret version
    SecretStore-->>API: secret_ref
    API->>Config: update upstream credential version
    Config-->>Runtime: publish snapshot
    Runtime->>Provider: health check with new credential
    Runtime-->>Config: credential status
```

Rotation policy should support:

- staged rotation with both old and new secret temporarily valid
- immediate revocation for compromised credentials
- scheduled expiration reminders
- validation before promotion when provider supports low-cost health checks
- audit events without secret material

## API Key Hashing

API keys and bearer caller credentials should be stored as salted hashes.

Required metadata:

| Field            | Meaning                          |
| ---------------- | -------------------------------- |
| `key_prefix`     | short display prefix             |
| `hash_algorithm` | hash algorithm                   |
| `hash_version`   | version for future rehash        |
| `last_used_at`   | last accepted request            |
| `last_used_ip`   | optional redacted remote address |
| `status`         | active, disabled, expired        |

Key lookup can use the prefix to narrow candidates, then constant-time hash
comparison for verification.

## Redaction Policy

Redaction policy applies to logs, traces, audit events, notification payloads,
debug captures, and admin read APIs.

Redaction levels:

| Level                      | Behavior                                                 |
| -------------------------- | -------------------------------------------------------- |
| `metadata_only`            | no prompt or completion text                             |
| `structured_safe`          | include safe counters and selected ids                   |
| `sampled_redacted_payload` | include truncated payload after filters                  |
| `explicit_capture`         | capture raw payload only with short-lived admin approval |

Default production level should be `metadata_only`.

## Sensitive Fields

Always redact:

- authorization headers
- provider API keys
- OAuth access tokens
- OAuth refresh tokens
- login authorization codes and login session cookies
- webhook signing secrets
- cookies
- raw API keys or caller credentials
- raw provider error bodies unless parsed and redacted
- prompt text unless explicit capture is enabled
- completion text unless explicit capture is enabled
- tool outputs unless policy classifies them as safe

The redaction library should be shared by runtime logging, admin audit, and
notification serialization.

## Debug Capture

Debug capture is useful but dangerous.

Requirements:

- disabled by default
- scoped by tenant, organization, project, credential, alias, or request id
- short retention window
- explicit actor and reason
- redaction policy applied before storage
- separate permission from ordinary viewer access
- notification or audit event when enabled and disabled

Raw capture should be avoided in the open-source default configuration.

## Audit Evidence

Audit evidence classes:

| Class              | Examples                                          |
| ------------------ | ------------------------------------------------- |
| admin mutation     | route policy changed, credential disabled         |
| runtime decision   | route target selected, candidate filtered         |
| security event     | invalid credential, denied scope, secret rotation |
| budget event       | threshold reached, request blocked                |
| notification event | webhook delivery failed                           |
| provider event     | endpoint degraded, credential expired             |

Audit records should include `tenant_id`, `organization_id` when applicable,
`request_id`, `trace_id`, actor or credential context, resource ids, and safe
diagnostics.

## Logging

Runtime logs should be structured.

Common log fields:

| Field                  | Meaning              |
| ---------------------- | -------------------- |
| `timestamp`            | event time           |
| `level`                | log severity         |
| `target`               | module or component  |
| `request_id`           | gateway request id   |
| `trace_id`             | distributed trace id |
| `tenant_id`            | tenant               |
| `organization_id`      | organization         |
| `project_id`           | project              |
| `model_alias`          | requested alias      |
| `routing_group_id`     | selected group       |
| `provider_endpoint_id` | selected endpoint    |
| `error_code`           | stable error code    |

Logs are for operators, not for reconstructing complete usage. Usage events and
route decisions are the durable evidence.

## Metrics

Use OpenTelemetry Metrics as the primary metrics instrumentation and export
surface. Runtime workers, admin workers, and background workers should emit
metrics through the same OpenTelemetry SDK and export them through OTLP to an
operator-selected collector/backend. Do not make DogStatsD, Prometheus client
libraries, or a vendor-specific API the v1 primary instrumentation path.

The gateway has three observability data planes:

| Plane                      | Primary Use                                                                                 | Source Of Truth                       |
| -------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------- |
| OpenTelemetry metrics      | operator-owned external dashboards, long-term provider performance, and alerts              | metrics backend through OTLP          |
| PostgreSQL evidence        | auditable usage, cost, route, config, and mutation history                                  | PostgreSQL tables and derived rollups |
| Redis-compatible hot state | built-in realtime dashboard, live counters, health hints, stickiness, and dynamic decisions | never durable; rebuilt or reconciled  |

OpenTelemetry metrics are operational telemetry exported for the operator's own
monitoring stack. They can power external dashboards and long-term provider
performance comparisons, but they do not replace durable usage events, cost
ledgers, route decisions, or audit events. Redis-compatible hot-state values
power the gateway's built-in realtime dashboard and dynamic decisions, but they
are not the long-term monitoring store.

Metric families:

| Metric                         | Dimensions                                            |
| ------------------------------ | ----------------------------------------------------- |
| request count                  | tenant, org, project, member, alias, protocol, status |
| request latency                | protocol, alias, route group, endpoint, status        |
| time to first token            | protocol, alias, target, endpoint                     |
| stream duration                | alias, target, endpoint, status                       |
| token throughput               | alias, target, endpoint                               |
| provider error count           | endpoint, provider kind, error class                  |
| route filter count             | reason, policy, group                                 |
| failover count                 | group, from endpoint, to endpoint, reason             |
| budget block count             | scope, policy, reason                                 |
| rate limit count               | scope, policy                                         |
| dashboard freshness lag        | scope, rollup kind                                    |
| usage rollup lag               | tenant, org, project                                  |
| model observability rollup lag | alias, target, endpoint                               |
| notification delivery count    | sink, event type, status                              |
| config publication lag         | tenant, snapshot status                               |
| secret resolution failure      | backend, purpose                                      |

Provider performance metrics should be emitted for both terminal requests and
upstream attempts:

| Metric                            | Purpose                                                              |
| --------------------------------- | -------------------------------------------------------------------- |
| `gateway.provider.request.count`  | provider attempt volume by endpoint, target, status, and error class |
| `gateway.provider.latency`        | long-term latency histograms by endpoint, target, and protocol       |
| `gateway.provider.ttft`           | time-to-first-token histograms for streaming-capable targets         |
| `gateway.provider.throughput`     | output tokens per second for comparable provider/model routes        |
| `gateway.provider.error.count`    | provider error, throttling, timeout, and auth failure trends         |
| `gateway.provider.failover.count` | failover volume and source/destination endpoint patterns             |
| `gateway.provider.health.state`   | current observed health class exported as an asynchronous gauge      |

Metric names should use the `gateway.` namespace until a stable semantic
convention is adopted. Histograms are required for latency, TTFT, stream
duration, and provider attempt duration. Counters are required for requests,
attempts, errors, failovers, budget blocks, rate-limit rejections, and
notification deliveries. Gauges are allowed for worker loaded config version,
queue depth, collector/exporter health, dashboard freshness lag, and current
provider health class.

High-cardinality labels should be controlled. Avoid raw request ids and raw
model ids as unbounded metric labels unless the backend supports exemplars.
Tenant, organization, project, project member, API key, and user labels are
allowed only when explicitly enabled by policy and retention controls. Default
metrics should prefer bounded identifiers such as protocol family, route group,
model alias, model target, provider endpoint, provider kind, status class,
error class, and region.

Metric export requirements:

- support OTLP/HTTP first, and reject `otlp_grpc` configs until a real gRPC
  transport is implemented
- support periodic export interval, timeout, and retry configuration
- tolerate collector outages without blocking model requests
- expose exporter failure count and dropped metric count
- redact secret-like labels and resource attributes before export
- support exemplars only when prompt, response, and secret data cannot leak
- keep metric schema names and units versioned in docs and OpenAPI examples

OTLP/HTTP requests use bounded JSON payloads and secret-backed headers from
`OpenTelemetryExportConfig`. Export evidence records response status class,
failure counts, dropped metric counts, and last successful export timestamp. It
must not store collector auth header values, raw prompts, raw responses, or raw
provider payloads. Local and test profiles may use loopback HTTP collectors for
deterministic integration tests; production collector endpoints must use HTTPS.

`OpenTelemetryExportConfig` is the admin-managed resource for exporting
telemetry to an operator-owned collector/backend.

| Field                     | Meaning                                                |
| ------------------------- | ------------------------------------------------------ |
| `otel_export_config_id`   | stable id                                              |
| `tenant_id`               | owning tenant or system scope                          |
| `signals`                 | `metrics`; traces and logs are outside v1              |
| `protocol`                | `otlp_http`; `otlp_grpc` is rejected until implemented |
| `endpoint`                | collector endpoint URL                                 |
| `headers_secret_ref_id`   | optional secret reference id for exporter headers      |
| `resource_attributes`     | bounded deployment attributes                          |
| `metric_temporality`      | cumulative or delta, if supported by selected backend  |
| `export_interval_seconds` | periodic metrics export interval                       |
| `export_timeout_seconds`  | exporter request timeout                               |
| `enabled`                 | whether the exporter is active                         |
| `status`                  | last validation and export health                      |

Read APIs return exporter metadata and health only. They must not return raw
headers, auth tokens, or other exporter secrets. A missing or unhealthy
OpenTelemetry exporter must not disable the built-in realtime dashboard.

Recommended dashboard inputs:

| Dashboard Area                     | Primary Input                                                  |
| ---------------------------------- | -------------------------------------------------------------- |
| built-in realtime operations       | Redis-compatible hot state plus recent route decision evidence |
| built-in usage and cost analytics  | PostgreSQL usage events, ledger buckets, and cost rollups      |
| built-in audit and compliance      | PostgreSQL audit events and route decision evidence            |
| operator-owned provider dashboards | OpenTelemetry metric histograms exported through OTLP          |
| operator-owned worker dashboards   | OpenTelemetry runtime metrics and readiness endpoints          |

If a metrics backend is unavailable, the gateway should continue serving
according to policy. The built-in realtime dashboard should continue to use
Redis-compatible hot state and readiness data. Operator-owned OTel dashboards
may show degraded monitoring freshness, but runtime authorization, budget,
route, and usage behavior must not depend on the metrics backend.

## Tracing

Trace spans:

```mermaid
flowchart TD
    request[model request]
    auth[authenticate client]
    authorize[authorize scope]
    budget[budget preflight]
    route[route selection]
    adapt[provider adaptation]
    upstream[upstream call]
    stream[stream processing]
    usage[usage accounting]
    notify[notification enqueue]

    request --> auth
    auth --> authorize
    authorize --> budget
    budget --> route
    route --> adapt
    adapt --> upstream
    upstream --> stream
    stream --> usage
    usage --> notify
```

Span attributes should use gateway-owned names:

- `gateway.tenant_id`
- `gateway.organization_id`
- `gateway.model_alias`
- `gateway.routing_group_id`
- `gateway.route_decision_id`
- `gateway.provider_endpoint_id`
- `gateway.error_code`

Do not place raw prompt or completion text in trace attributes.

## Health Model

Health is tracked at multiple layers:

| Layer               | Signal                                          |
| ------------------- | ----------------------------------------------- |
| process             | worker heartbeat, build info, config version    |
| database            | connectivity and migration version              |
| secret backend      | read/write capability                           |
| cache               | read/write and PubSub capability                |
| provider endpoint   | latency, error rate, auth failure, probe result |
| upstream credential | auth success, expiry, quota symptoms            |
| route target        | combined endpoint and model availability        |
| notification sink   | delivery success and retry backlog              |

Provider health should not be a single global bit. A provider endpoint can be
healthy for one model target and degraded for another.

## Readiness And Liveness

Liveness answers whether the process should be restarted. Readiness answers
whether it should receive traffic.

Readiness requirements:

- config snapshot loaded
- database connection available, unless worker is in read-only degraded mode
- secret backend available for selected credentials
- cache state available when rate limiting is configured fail-closed
- clock skew within configured tolerance

Workers may stay live while not ready.

## Degraded Modes

Degraded modes should be explicit:

| Mode                   | Behavior                                                                             |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `config_read_only`     | serve last-known-good config, reject admin writes                                    |
| `usage_buffering`      | buffer usage only for scopes without active hard budget enforcement                  |
| `fail_limited_cache`   | allow bounded requests when cache is unavailable and policy permits fail-limited use |
| `notification_delayed` | outbox grows but runtime traffic continues                                           |
| `provider_degraded`    | router avoids affected targets                                                       |
| `budget_conservative`  | block or restrict traffic when budget state is stale                                 |

Each degraded mode should emit metrics, logs, and audit or operational events.

## Storage Components

V1 production baseline storage split:

| Component                | Data                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------ |
| PostgreSQL               | config, audit, usage events, ledger, outbox                                          |
| Redis-compatible backend | realtime dashboard state, hot counters, config hints, health state, route stickiness |
| secret backend           | raw upstream secrets, login provider client secrets, and OAuth tokens                |
| object storage           | exports, optional redacted debug bundles                                             |

Local development may run without a Redis-compatible backend only in an
explicit limited profile. Production profiles should treat Redis or a
compatible hot-state backend as required for rate limits, budget hot counters,
route stickiness, circuit breakers, and config invalidation. PostgreSQL remains
the source of truth.

## Database Requirements

Database requirements:

- transactional config writes and audit events
- append-only usage and audit tables
- idempotency constraints for usage events and admin writes
- indexed scope and time filters
- migration version tracking
- soft delete and retention support
- support for offline backup and restore

Config and runtime evidence can share one database initially, but table design
should keep high-volume usage writes separate from low-volume config writes.

### Durable Schema Groups

PostgreSQL tables should be grouped by write pattern and retention profile.

| Group                   | Example Tables                                                                            | Write Pattern                 | Required Constraints                                      |
| ----------------------- | ----------------------------------------------------------------------------------------- | ----------------------------- | --------------------------------------------------------- |
| identity                | tenants, organizations, org members, project members, principals, role bindings, API keys | low-volume admin writes       | tenant scope, unique stable ids, soft delete              |
| provider catalog        | provider endpoints, upstream credentials, model targets, model aliases, pricing documents | low-volume admin writes       | protocol compatibility, immutable used pricing versions   |
| routing config          | routing groups, route policies, provider grants, config bundles, config snapshots         | low-volume admin writes       | monotonic config versions, snapshot immutability          |
| runtime evidence        | route decisions, route attempt events, authorization decisions                            | request-volume appends        | request id indexes, append-only rows, retention partition |
| usage and ledger        | usage events, cost estimates, ledger buckets, reservations, ledger adjustments            | high-volume appends and folds | idempotency key, fixed-point units, pricing version       |
| dashboard rollups       | usage rollups, model observability rollups, member usage rollups, budget posture rollups  | derived writes                | source watermark, scope, time bucket, freshness metadata  |
| budget and quota policy | budget policies, quota policies, reset schedules, enforcement overrides                   | admin writes plus reads       | scope uniqueness, effective time ranges                   |
| notification delivery   | notification sinks, subscriptions, outbox events, delivery attempts                       | append and retry updates      | idempotency key, receiver event id, retry state           |
| audit                   | admin audit events, emergency actions, redacted diffs, policy publication records         | append-only                   | actor id, resource id, config version                     |
| operations              | migration history, worker heartbeats, config load status, incident markers                | low-volume operational writes | monotonic timestamps, worker id indexes                   |

High-volume tables should be partitionable by tenant and time before production
traffic moves through the gateway. Partitioning is an implementation detail, but
queries and retention jobs must not require scanning all tenants.

### Transaction Patterns

| Operation               | Transaction Requirement                                                              |
| ----------------------- | ------------------------------------------------------------------------------------ |
| admin mutation          | write resource change, redacted diff, audit event, and idempotency record atomically |
| config publish          | write immutable snapshot and advance version pointer atomically                      |
| route decision start    | write route decision header before first upstream attempt                            |
| route attempt append    | append attempt event without mutating prior attempt evidence                         |
| usage terminal write    | write usage event once per request/idempotency key                                   |
| ledger fold             | fold usage into aggregate bucket with idempotent processed-event marker              |
| notification enqueue    | append outbox event in same logical flow as usage/audit source                       |
| hard budget reservation | reserve or reject in one transaction when strong preflight mode is enabled           |

Any path that buffers writes during a dependency outage must document which
durability and budget guarantees are suspended. Hard-capped scopes cannot use
unbounded write buffering as a substitute for durable ledger writes.

## Cache Requirements

A Redis-compatible backend such as Redis or Valkey is the shared hot-state
backend. It is not a source of truth.
Durable resources, configuration, usage events, cost ledger buckets, audit
events, and notification outbox records live in PostgreSQL.

Cache uses must be limited to low-latency state that can be rebuilt, ignored,
or reconciled:

- built-in realtime operations dashboard views
- rate limit counters
- budget hot counters
- route stickiness keys
- provider health windows
- circuit breaker state
- config invalidation messages
- short-lived concurrency leases

Cache loss behavior is policy-specific. Runtime code should not assume cache is
durable evidence.

### Key Naming

All keys must use gateway-owned names and tenant scope unless the data is
explicitly global:

```text
gateway:{domain}:{tenant_id}:{scope...}:{version_or_window}
```

Rules:

- include `tenant_id` for tenant data
- include `policy_id` for policy-owned counters
- include `config_version` or policy version when stale values can affect
  routing or policy
- hash or normalize user-provided affinity values before putting them in keys
- never include raw API key material, prompt text, completion text, upstream
  credential values, OAuth tokens, or secret reference payloads
- keep key names stable enough for dashboards and runbooks

### Key Classes

Cache entries must have an owner, TTL, recovery path, and failure mode. Keys
without TTL require an explicit exception in the owning spec.

| Entry Type             | Owner            | Required TTL              | Recovery Path                         | Default Failure Mode       |
| ---------------------- | ---------------- | ------------------------- | ------------------------------------- | -------------------------- |
| rate limit counter     | quota policy     | policy window plus grace  | durable usage or fresh empty window   | policy-defined             |
| budget hot counter     | budget policy    | reset window plus grace   | durable ledger bucket reconciliation  | fail closed for hard caps  |
| route stickiness       | route policy     | sticky policy TTL         | route without affinity                | degrade optimization       |
| provider health window | health policy    | short rolling window      | unknown until fresh probe or traffic  | health unknown             |
| circuit breaker        | endpoint policy  | breaker cool-down TTL     | config state and fresh attempt errors | closed only if policy says |
| config invalidation    | config publisher | message only              | database version polling              | converge through polling   |
| concurrency lease      | quota policy     | request deadline plus lag | lease expiry and terminal audit       | policy-defined             |
| request lease          | runtime request  | request deadline plus lag | terminal request cleanup              | request-scoped             |
| authn failure window   | auth policy      | short failure window      | fresh empty window                    | policy-defined             |

Example key shapes:

| Domain        | Example Shape                                                                          |
| ------------- | -------------------------------------------------------------------------------------- |
| rate          | `gateway:rate:{tenant}:{policy_id}:{scope_kind}:{scope_id}:{window}`                   |
| budget        | `gateway:budget:{tenant}:{policy_id}:{scope_kind}:{scope_id}:{reset_window}`           |
| concurrent    | `gateway:concurrent:{tenant}:{policy_id}:{scope_kind}:{scope_id}`                      |
| request lease | `gateway:lease:{tenant}:{request_id}:{lease_kind}`                                     |
| sticky        | `gateway:sticky:{tenant}:{project_id}:{model_alias_id}:{affinity_hash}`                |
| health        | `gateway:health:{tenant}:{provider_endpoint_id}:{window}`                              |
| circuit       | `gateway:circuit:{tenant}:{provider_endpoint_id}:{reason}`                             |
| config        | `gateway:config:loaded:{worker_id}` and `gateway:config:invalidate:{tenant_or_global}` |
| authn         | `gateway:authn_fail:{tenant_or_global}:{credential_prefix_or_ip}:{window}`             |

### Atomicity

Use a single Redis command or Lua script when multiple operations must be
observed as one policy decision.

Required atomic operations:

- check and increment request or token counters
- reserve budget hot counters when projected cost stays within allowance
- acquire and release concurrency leases idempotently
- update circuit breaker state with compare-and-set semantics
- write sticky mapping only when the target remains eligible for the active
  config version

Script outputs should return structured decision data and must not include
secret material:

```json
{
  "allowed": true,
  "policy_id": "pol_...",
  "counter_value": 42,
  "limit": 100,
  "reset_at": "2026-06-24T00:01:00Z",
  "mode": "normal"
}
```

### Failure Modes

Default behavior under cache loss:

| Capability       | Cache Unavailable Default                                     |
| ---------------- | ------------------------------------------------------------- |
| route stickiness | ignore sticky mapping and route from current config           |
| provider health  | treat health as unknown unless config marks endpoint disabled |
| circuit breaker  | use config state and fresh attempts; do not infer durability  |
| soft budget      | allow or notify according to budget policy                    |
| hard budget      | fail closed unless policy declares bounded fail-limited mode  |
| rate limit       | policy-defined `fail_open`, `fail_limited`, or `fail_closed`  |
| concurrency      | policy-defined; production defaults should be conservative    |
| config reload    | rely on PostgreSQL version polling                            |

Any fail-limited mode must define:

- maximum requests
- maximum estimated cost or tokens
- time window
- affected scopes
- audit event shape
- operator alert

### Reconciliation

Hot-state values that affect spend controls are reconciled from PostgreSQL
evidence:

1. Usage events append to durable storage.
2. Ledger workers fold usage into durable buckets.
3. Reconciliation compares hot budget counters with durable bucket totals.
4. Differences are repaired when safe.
5. Hard-capped scopes enter conservative mode when hot state is lower than
   durable usage or cannot be trusted.
6. Repairs that affect enforcement write audit evidence.

Rate counters are short-lived and may not need durable repair, but usage and
budget counters need reconciliation because they affect spend controls.

### Deployment

V1 should support:

- local single-node Redis or Valkey through Docker Compose
- production managed Redis or Valkey with TLS
- Sentinel or managed failover when operator infrastructure provides it

The gateway should not require Redis Cluster in v1. If Redis Cluster is used,
scripts and multi-key operations must keep keys in a compatible hash slot or be
disabled for policies that require cross-key atomicity.

The Redis-compatible deployment must support the atomic operations required by
the enabled policies. If the selected deployment mode cannot provide the needed
atomic compare/increment or lease semantics, that policy cannot be enabled in
production.

### Observability And Tests

Minimum metrics:

- cache command latency
- script latency by script id
- cache error count by operation
- cache unavailable duration
- budget conservative mode count
- fail-limited allowance consumed
- config invalidation lag
- worker loaded config version
- reconciliation repair count

Logs must use key class and scope metadata, not full raw key strings when keys
could contain hashed affinity or customer-controlled identifiers.

Required tests:

- key construction rejects unsafe input
- every key class has TTL or an explicit exception
- atomic scripts enforce limits under concurrent requests
- hard budget cache loss fails according to policy
- missed PubSub invalidation converges through polling
- reconciliation repairs stale hot counters
- sticky routing degrades safely when cache is unavailable
- hot-state backend restart during a streaming request does not lose usage
  evidence

Acceptance gates:

- Redis-compatible hot state is never the source of truth for durable gateway
  evidence.
- Each hot-state key has owner, TTL, scope, failure mode, and recovery path.
- Atomic policies are backed by scripts or single-command guarantees.
- Production hard budget behavior is conservative under cache loss.
- Local validation can run Postgres and Redis or Valkey through compose or
  `testcontainers`.

## Backup And Restore

Backup scope:

| Data                    | Backup Requirement                                 |
| ----------------------- | -------------------------------------------------- |
| config database         | required                                           |
| audit events            | required                                           |
| usage events and ledger | required unless exported and intentionally dropped |
| outbox                  | required for delivery continuity if not expired    |
| secret backend          | required, separate procedure                       |
| object exports          | required according to retention policy             |

Restore must account for secret references. A database restore without the
matching secret backend can preserve metadata but cannot serve upstream traffic.

## Migration Policy

Migrations should be forward-only by default. Destructive migrations require a
documented data retention decision.

Migration requirements:

- migration id and checksum tracked
- schema migrations run before new worker version becomes ready
- long backfills can run separately from startup
- rollback plan documented for every release
- config schema version compatibility checked during startup
- usage export schema versioned independently from database schema

## Deployment Topologies

Supported topologies:

| Topology                                             | Use                          |
| ---------------------------------------------------- | ---------------------------- |
| single binary, embedded storage                      | local development only       |
| single service plus database                         | small self-hosted deployment |
| stateless workers plus database/cache/secret backend | production                   |
| separated admin and runtime workers                  | enterprise production        |
| multi-region runtime, regional control plane         | later phase                  |

Admin and runtime can live in one binary initially, but internal boundaries
should allow splitting.

## Runtime Worker Classes

Worker classes:

| Worker              | Responsibility                      |
| ------------------- | ----------------------------------- |
| ingress worker      | handles model requests              |
| admin worker        | handles config and evidence APIs    |
| accounting worker   | aggregates usage and budgets        |
| notification worker | delivers outbox events              |
| health worker       | probes endpoints and updates health |
| export worker       | writes usage export files           |

Small deployments can run all workers in one process. Large deployments can
scale runtime and notification workers independently.

## Multi-Region Direction

Multi-region introduces consistency decisions:

- config publication should be region-aware
- budget enforcement can be regional with central reconciliation or strongly
  centralized for strict caps
- route health is regional
- provider endpoints may be region-specific
- notification delivery should avoid duplicate cross-region deliveries
- usage event ids must be globally unique

The v1 gateway should not require multi-region, but schemas should not prevent
it.

## Provider Operations

Provider operations include:

- endpoint creation and validation
- upstream credential rotation
- health probes
- quota and rate-limit symptom detection
- provider incident annotations
- planned maintenance drain
- emergency disable

Provider health should combine passive request outcomes and optional active
probes. Active probes must be low-cost and respect provider terms.

## Budget Operations

Budget operations include:

- view current period usage
- inspect budget threshold history
- reset or replace policy
- force block or unblock scope
- export ledger details
- reconcile missing usage
- adjust cost for pricing correction

Every manual budget operation writes an audit event and can emit a notification
event.

## Notification Operations

Notification operations include:

- test sink delivery with synthetic event
- replay dead-lettered event
- pause sink
- resume sink
- rotate webhook signing secret
- inspect delivery attempts
- export dead letters

Replay must preserve the original event id unless an operator explicitly emits a
new synthetic event.

## Incident Response

Common incident actions:

| Incident            | Action                                                                   |
| ------------------- | ------------------------------------------------------------------------ |
| upstream key leaked | disable upstream credential, rotate secret, audit affected route targets |
| API key leaked      | disable API key, inspect recent usage, issue replacement                 |
| provider outage     | drain endpoint or route group, lower weights, monitor failover           |
| runaway spend       | force budget block, inspect usage by scope, notify external system       |
| bad config publish  | rollback snapshot, freeze config if needed                               |
| webhook storm       | pause sink, inspect backlog, adjust filters                              |
| usage ledger lag    | switch to conservative budget mode, run reconciliation                   |

Incident tools should be available through admin API and CLI, not only through
manual database edits.

## Data Retention Operations

Retention policy should be explicit per data class:

- usage events
- aggregated ledger buckets
- audit events
- route decisions
- notification outbox payloads
- delivery attempts
- debug captures
- provider health samples
- admin request logs

Retention jobs should produce deletion summaries and audit events. They should
not delete immutable evidence required by active budgets or unresolved exports.

## Compliance Posture

The gateway should make compliance possible without claiming a certification.

Capabilities:

- role-based admin access
- secret isolation
- immutable audit events
- redaction controls
- configurable retention
- data export
- deletion workflow for debug captures
- scoped provider grants

Certification, legal policy, and customer-specific data processing terms remain
deployment responsibilities.

## Configuration Defaults

Secure production defaults:

| Setting                         | Default                           |
| ------------------------------- | --------------------------------- |
| prompt capture                  | disabled                          |
| completion capture              | disabled                          |
| admin audit                     | enabled                           |
| runtime route decision evidence | enabled                           |
| webhook signing                 | required                          |
| secret backend                  | external or encrypted database    |
| cache failure for rate limits   | fail limited                      |
| budget stale behavior           | conservative when hard caps exist |
| debug capture retention         | short                             |
| route failover after content    | disabled                          |

Local development can use weaker defaults only under an explicit profile.

## Operational Dashboards

Minimum dashboards:

- request volume and error rate by alias and endpoint
- latency and time to first token by endpoint
- route target selection share by routing group
- provider error classes and failover count
- budget usage and threshold events
- cache and database health
- notification backlog and delivery failures
- config publication lag and runtime snapshot versions
- secret expiry and credential failure count

Built-in realtime dashboards should use Redis-compatible hot state and safe
operational evidence. Operator-owned long-term dashboards should use
OpenTelemetry metrics and durable audit/usage data. No dashboard should use raw
prompt capture.

## Alerting

Alert examples:

| Alert                         | Trigger                                  |
| ----------------------------- | ---------------------------------------- |
| provider endpoint unavailable | sustained error rate or probe failure    |
| credential auth failure       | repeated unauthorized upstream responses |
| config publication stalled    | snapshot not applied within threshold    |
| usage ledger lag              | usage event backlog exceeds threshold    |
| hard budget reached           | budget policy enters block state         |
| notification backlog          | pending delivery count too high          |
| secret expires soon           | credential expiry within threshold       |
| cache unavailable             | cache health check failure               |
| database migration mismatch   | worker schema incompatible               |

Alerts should include runbook links once runbooks exist.

## Runbook Requirements

Each production feature should include a short runbook:

- symptoms
- dashboard links or metric names
- likely causes
- safe immediate actions
- verification steps
- rollback steps
- escalation path

Runbooks can live in `docs/operations.md` once implementation begins.

## Acceptance Gates

- No raw upstream secret, OAuth token, webhook signing secret, or client
  credential can be returned by admin read APIs.
- Default logs, traces, usage events, audit events, and notifications exclude
  raw prompts and raw completions.
- Secret rotation can be audited and propagated to runtime workers.
- Runtime workers expose readiness, liveness, build info, and config version.
- Provider health is tracked per endpoint and can influence routing.
- Usage and audit stores support backup, restore, and retention.
- Notification failures are observable and replayable without blocking model
  serving.
- Production deployment can run admin, runtime, accounting, notification, and
  health workers as separate roles.
- Incident actions are available through admin API or CLI and emit audit events.
