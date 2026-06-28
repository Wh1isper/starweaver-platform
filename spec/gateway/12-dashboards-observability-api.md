# Dashboards, Usage Analytics, And Model Observability API

Status: design draft for review.

This spec defines read APIs for dashboards, usage analytics, and model
observability. These APIs are first-class gateway APIs. They are not UI-only
queries and they must use the same organization, project, membership, and
authorization model as protocol ingress and admin APIs.

## Goals

- Provide scoped dashboards for tenant-scoped roles, organizations, projects,
  and project members.
- Answer "what did this person consume in this project" without recomputing
  authorization history from mutable membership tables.
- Expose usage, cost, latency, model health, routing, failover, and provider
  error information in dashboard-friendly shapes.
- Keep raw prompts, completions, API keys, upstream secrets, and OAuth tokens
  out of every dashboard response.
- Make aggregation semantics stable enough for external BI and internal UI
  clients.

## Non-Goals

- Do not implement paid billing, invoices, seats, plans, or payment reporting.
- Do not expose raw request/response payloads as dashboard data.
- Do not require a specific frontend charting framework.
- Do not make dashboards depend on live provider credentials.

## Scope Model

Dashboard APIs are scoped by the user's effective authorization.

| Scope             | Typical Actor                                          | Resource Boundary                                        |
| ----------------- | ------------------------------------------------------ | -------------------------------------------------------- |
| tenant            | `tenant_owner`, `tenant_admin`, `gateway_operator`     | all organizations and projects in a tenant               |
| organization      | `organization_admin`, `organization_member`            | one organization and its projects                        |
| project           | `project_admin`, `project_developer`, `project_viewer` | one project                                              |
| project member    | `project_developer`, `project_viewer`, `project_admin` | one user's usage inside one project                      |
| API key           | key owner, `project_admin`, `auditor`                  | one API key                                              |
| service account   | service account owner, `project_admin`, `auditor`      | one service account or service-owned credential          |
| model alias       | organization/project model viewer                      | one client-visible model alias                           |
| model target      | `gateway_operator`, `security_admin`                   | one upstream model target                                |
| provider endpoint | `gateway_operator`, `security_admin`                   | one upstream endpoint, account, region, or provider kind |

Project member usage is keyed by immutable `project_member_id` recorded on
usage events. If a user is removed from a project later, historical usage
remains attributable to the member record that existed at request time.

## Dashboard Families

| Family                  | Purpose                                                                   |
| ----------------------- | ------------------------------------------------------------------------- |
| realtime operations     | Redis-compatible live routing, budget, quota, provider, and worker status |
| overview                | request, token, cost, budget, and error summary by scope                  |
| usage                   | usage and estimated cost broken down by member, project, key, model       |
| model observability     | latency, TTFT, throughput, errors, usage confidence, and routing          |
| provider observability  | provider endpoint health, failover, retry, throttling, and credential     |
| budget and quota        | spend, remaining budget, burn rate, hard blocks, rate-limit pressure      |
| route diagnostics       | filtered targets, selected targets, failover, sticky routing impact       |
| notification operations | outbox backlog, delivery success, retry, disabled sinks                   |

## Common Query Parameters

Dashboard APIs should use consistent query parameters.

| Parameter              | Meaning                                           |
| ---------------------- | ------------------------------------------------- |
| `scope_kind`           | tenant, organization, project, member, key, model |
| `scope_id`             | id for the selected scope                         |
| `organization_id`      | optional organization filter                      |
| `project_id`           | optional project filter                           |
| `project_member_id`    | optional member filter                            |
| `principal_id`         | optional user/service account filter              |
| `api_key_id`           | optional API key filter                           |
| `model_alias_id`       | optional model alias filter                       |
| `model_target_id`      | optional upstream target filter                   |
| `provider_endpoint_id` | optional provider endpoint filter                 |
| `time_start`           | inclusive start timestamp                         |
| `time_end`             | exclusive end timestamp                           |
| `granularity`          | minute, hour, day, week, month                    |
| `group_by`             | one or more supported dimensions                  |
| `status`               | success, error, partial, blocked, canceled        |
| `usage_confidence`     | exact, partial, estimated, missing                |
| `cursor`               | opaque cursor for tabular rows                    |
| `limit`                | bounded page size                                 |

Time ranges must be bounded. The service should reject expensive unbounded
queries and ask callers to use exports for large historical scans.

## Common Response Envelope

```json
{
  "schema": "gateway.dashboard.response.v1",
  "scope": {
    "scope_kind": "project",
    "scope_id": "prj_...",
    "tenant_id": "ten_...",
    "organization_id": "org_...",
    "project_id": "prj_..."
  },
  "window": {
    "start": "2026-06-24T00:00:00Z",
    "end": "2026-06-25T00:00:00Z",
    "granularity": "hour"
  },
  "data_freshness": {
    "ledger_lag_seconds": 12,
    "usage_event_watermark": "2026-06-24T23:59:00Z",
    "partial": false
  },
  "series": [],
  "totals": {},
  "next_cursor": null
}
```

`data_freshness.partial` is true when aggregation is missing recent events,
ledger folding is behind, or a provider usage gap affects the requested scope.

## Realtime Operations Dashboard API

The built-in realtime dashboard is an operational view backed primarily by a
Redis-compatible hot-state backend such as Redis or Valkey. It answers "what is
happening now" for operators and authorized admins.

Example endpoints:

| Endpoint                           | Purpose                                                |
| ---------------------------------- | ------------------------------------------------------ |
| `GET /admin/v1/realtime/overview`  | live request, budget, quota, and health posture        |
| `GET /admin/v1/realtime/providers` | provider endpoint health, circuit, and throttle hints  |
| `GET /admin/v1/realtime/routes`    | sticky routing, recent route pressure, and drain state |
| `GET /admin/v1/realtime/budgets`   | hot budget pressure and conservative-mode state        |
| `GET /admin/v1/realtime/quotas`    | live rate, token, and concurrency pressure             |
| `GET /admin/v1/realtime/workers`   | loaded config version and worker heartbeat hints       |

Realtime response fields must include:

- source key class, not raw hot-state key
- source freshness timestamp
- TTL or expiry when applicable
- config version or policy version when the value affects decisions
- whether the value is authoritative, approximate, stale, or unavailable
- fallback explanation when hot-state data is missing

Realtime dashboard values must never be the only place a durable decision is
recorded. Route decisions, usage, cost, and audit evidence still come from
durable stores.

## Overview Dashboard API

Example endpoints:

| Endpoint                                         | Scope                       |
| ------------------------------------------------ | --------------------------- |
| `GET /admin/v1/dashboards/tenant/overview`       | tenant operator             |
| `GET /admin/v1/dashboards/organizations/{id}`    | organization overview       |
| `GET /admin/v1/dashboards/projects/{id}`         | project overview            |
| `GET /admin/v1/dashboards/project-members/{id}`  | one member's project usage  |
| `GET /admin/v1/dashboards/api-keys/{id}`         | one API key's usage         |
| `GET /admin/v1/dashboards/service-accounts/{id}` | one service account's usage |

Overview measures:

| Measure                 | Meaning                                     |
| ----------------------- | ------------------------------------------- |
| `request_count`         | terminal requests                           |
| `success_count`         | successful requests                         |
| `error_count`           | gateway or provider errors                  |
| `blocked_count`         | budget, quota, policy, or route blocks      |
| `input_tokens`          | normalized input tokens                     |
| `output_tokens`         | normalized output tokens                    |
| `reasoning_tokens`      | reasoning/thinking token units              |
| `media_units`           | image/audio/provider-specific media units   |
| `estimated_cost`        | fixed-point provider cost estimate          |
| `budget_remaining`      | remaining configured budget when applicable |
| `burn_rate`             | spend or usage velocity for selected window |
| `p50_latency_ms`        | median request latency                      |
| `p95_latency_ms`        | 95th percentile request latency             |
| `p99_latency_ms`        | 99th percentile request latency             |
| `p50_ttft_ms`           | median time to first token                  |
| `provider_error_rate`   | provider error count divided by attempts    |
| `usage_missing_count`   | events with missing usage                   |
| `usage_estimated_count` | events using estimated usage                |

## Usage Analytics API

Usage analytics returns tabular breakdowns and time series.

Example endpoints:

| Endpoint                                             | Purpose                                      |
| ---------------------------------------------------- | -------------------------------------------- |
| `GET /admin/v1/usage/summary`                        | aggregate usage by requested scope           |
| `GET /admin/v1/usage/timeseries`                     | time series usage and cost                   |
| `GET /admin/v1/usage/breakdown/by-project`           | organization projects ranked by usage        |
| `GET /admin/v1/usage/breakdown/by-project-member`    | users inside a project ranked by consumption |
| `GET /admin/v1/usage/breakdown/by-model`             | model alias or target usage                  |
| `GET /admin/v1/usage/breakdown/by-provider-endpoint` | provider endpoint usage and cost             |
| `GET /admin/v1/usage/events`                         | paginated event rows                         |

Supported group-by dimensions:

- organization
- project
- project member
- principal
- API key
- service account
- model alias
- model target
- route policy
- routing group
- provider endpoint
- protocol family
- status
- usage confidence
- error class

For "person in project" views, prefer `project_member_id` over `principal_id`
because membership role, display name, and status can change over time.

## Model Observability API

Model observability focuses on model-facing behavior, not user billing.

Example endpoints:

| Endpoint                                                            | Purpose                                 |
| ------------------------------------------------------------------- | --------------------------------------- |
| `GET /admin/v1/models/aliases/{id}/dashboard`                       | alias-level latency, usage, errors      |
| `GET /admin/v1/models/targets/{id}/dashboard`                       | upstream target latency, usage, errors  |
| `GET /admin/v1/models/aliases/{id}/routes`                          | selected routes, filtered targets       |
| `GET /admin/v1/models/aliases/{id}/quality`                         | usage confidence and provider error mix |
| `GET /admin/v1/provider-endpoints/{id}/observability/model-targets` | endpoint/model health by target         |

Measures:

| Measure                   | Meaning                                      |
| ------------------------- | -------------------------------------------- |
| `request_count`           | terminal model requests                      |
| `attempt_count`           | upstream attempts                            |
| `success_rate`            | successful requests divided by requests      |
| `provider_error_rate`     | upstream provider errors divided by attempts |
| `gateway_error_rate`      | gateway failures divided by requests         |
| `p50_latency_ms`          | median request latency                       |
| `p95_latency_ms`          | 95th percentile request latency              |
| `p99_latency_ms`          | 99th percentile request latency              |
| `p50_ttft_ms`             | median time to first token                   |
| `p95_ttft_ms`             | 95th percentile time to first token          |
| `tokens_per_second`       | output token throughput                      |
| `input_tokens`            | normalized input tokens                      |
| `output_tokens`           | normalized output tokens                     |
| `estimated_cost`          | fixed-point provider cost                    |
| `failover_count`          | requests that moved to another target        |
| `filtered_target_count`   | candidates filtered by reason                |
| `sticky_hit_count`        | requests using sticky route affinity         |
| `usage_confidence_counts` | exact, partial, estimated, missing counts    |

Model dashboards can show provider names, model aliases, target ids, endpoint
ids, status classes, and latency/cost metrics. They must not show prompt text,
completion text, upstream credential ids to unauthorized actors, raw provider
headers, or request bodies.

## Provider Observability API

Provider observability is more privileged because it can reveal upstream
account, region, credential, and operational posture.

Example endpoints:

| Endpoint                                                          | Purpose                                      |
| ----------------------------------------------------------------- | -------------------------------------------- |
| `GET /admin/v1/provider-endpoints/{id}/observability/health`      | health windows, breaker state, recent errors |
| `GET /admin/v1/provider-endpoints/{id}/observability/usage`       | usage and cost through one endpoint          |
| `GET /admin/v1/provider-endpoints/{id}/observability/failover`    | failover in/out, error classes               |
| `GET /admin/v1/provider-endpoints/{id}/observability/credentials` | masked credential status and rotation state  |

Organization and project viewers may see redacted provider labels only when the
provider endpoint is granted to their scope. Tenant operators and security
admins can see full operational metadata except raw secrets.

## Budget And Quota Dashboard API

Budget dashboards expose cost-control state.

Example endpoints:

| Endpoint                                    | Purpose                                      |
| ------------------------------------------- | -------------------------------------------- |
| `GET /admin/v1/budgets/dashboard`           | budget posture for authorized scopes         |
| `GET /admin/v1/budgets/{id}/timeseries`     | spend and remaining budget over time         |
| `GET /admin/v1/quotas/dashboard`            | rate and quota pressure                      |
| `GET /admin/v1/rate-limits/{id}/timeseries` | limit usage, rejection count, cache behavior |

Budget dashboard responses must identify whether values come from durable
ledger buckets, hot counters, estimates, or a conservative stale-state mode.

## OpenTelemetry Export Configuration API

OpenTelemetry export configuration is an admin-managed observability surface,
not the storage backend for the built-in realtime dashboard. The gateway emits
bounded metrics through OTLP so operators can build their own long-term
dashboards in their metrics backend.

The v1 worker sends OTLP/HTTP metrics as bounded JSON payloads with
secret-backed collector headers. Local and test profiles may use loopback HTTP
collectors for deterministic integration tests; production collector endpoints
must use HTTPS. `otlp_grpc` configs are rejected until a real gRPC transport is
implemented, so unsupported telemetry protocols fail during validation instead
of becoming periodic exporter failures.

Example endpoints:

| Endpoint                                                         | Purpose                                     |
| ---------------------------------------------------------------- | ------------------------------------------- |
| `GET /admin/v1/observability/otel-export/configs`                | list exporter configs and safe health state |
| `GET /admin/v1/observability/otel-export/configs/{id}`           | read one exporter config and health         |
| `POST /admin/v1/observability/otel-export/configs`               | create exporter config                      |
| `PATCH /admin/v1/observability/otel-export/configs/{id}`         | update endpoint, signals, headers, labels   |
| `POST /admin/v1/observability/otel-export/configs/{id}/validate` | validate without publishing                 |
| `POST /admin/v1/observability/otel-export/configs/{id}/disable`  | disable exporter config                     |

Read responses return endpoint host, enabled signals, bounded resource
attributes, export interval, timeout, last validation status, exporter failure
count, dropped metric count, and last successful export timestamp. They never
return raw headers, auth tokens, or secret locators beyond masked
`secret_ref_id` metadata.

Exporter failures degrade operator-owned dashboards only. They must not block
model requests, authorization, route selection, usage recording, or the
built-in realtime dashboard.

## Authorization

Dashboard APIs require explicit read actions.

| Action                                   | Resource                                   |
| ---------------------------------------- | ------------------------------------------ |
| `gateway.realtime_dashboard.read`        | Redis-compatible realtime dashboard scope  |
| `gateway.dashboard.tenant.read`          | tenant dashboard scope                     |
| `gateway.dashboard.organization.read`    | organization dashboard scope               |
| `gateway.dashboard.project.read`         | project dashboard scope                    |
| `gateway.dashboard.project_member.read`  | project member dashboard scope             |
| `gateway.dashboard.api_key.read`         | API key dashboard scope                    |
| `gateway.dashboard.service_account.read` | service account dashboard scope            |
| `gateway.usage.summary.read`             | usage aggregate scope                      |
| `gateway.usage.event.read`               | usage event rows                           |
| `gateway.model_observability.read`       | model alias or model target                |
| `gateway.provider_observability.read`    | provider endpoint operational metrics      |
| `gateway.budget_dashboard.read`          | budget policy or budget scope              |
| `gateway.quota_dashboard.read`           | quota or rate-limit scope                  |
| `gateway.observability_export.read`      | OpenTelemetry exporter metadata and health |
| `gateway.observability_export.write`     | OpenTelemetry exporter config              |

Authorization rules:

- `tenant_owner`, `tenant_admin`, and `gateway_operator` roles can read all
  dashboard scopes in the tenant
- `organization_admin` roles can read organization and project dashboards under
  their organization
- `organization_member` roles can read organization-level dashboards only when policy
  grants that view
- `project_admin` roles can read their project dashboard and project member usage
- `project_developer` and `project_viewer` roles can read their own usage in a project when policy permits
- `usage_viewer` roles can read aggregate usage for their assigned scope
- `auditor` roles can read event-level usage and route evidence according to redaction
  policy
- provider observability requires `gateway_operator` or `security_admin` unless
  the response is explicitly redacted to organization/project level
- OpenTelemetry export configuration requires
  `gateway.observability_export.read` or `gateway.observability_export.write`
  and strong redaction of header secret references

## Aggregation And Freshness

The gateway has one built-in realtime dashboard and separate analytics APIs.
The built-in realtime dashboard reads the Redis-compatible hot-state backend
plus recent safe operational evidence. It is for current operational posture,
not for historical reporting or audit. Usage, cost, route, and model analytics
APIs read from durable usage events, ledger buckets, route decision evidence,
and PostgreSQL rollups.

OpenTelemetry metrics are exported through operator configuration. They are the
recommended path for users to build their own long-term monitoring dashboards
in their own metrics backend. The gateway does not need to query the user's
OTel backend to render the built-in realtime dashboard.

Dashboard data sources have distinct roles:

| Source                     | Dashboard Use                                                                                                 | Constraint                                               |
| -------------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| PostgreSQL usage events    | auditable usage rows, cost attribution, and project member consumption                                        | source of truth for usage and cost                       |
| PostgreSQL ledger buckets  | billing-neutral cost rollups, budgets, and historical aggregate queries                                       | source of truth for cost windows                         |
| Route decision evidence    | routing, failover, filtered target, and attempt explanations                                                  | source of truth for route history                        |
| Redis-compatible hot state | built-in realtime budget pressure, rate pressure, health hints, circuit state, and sticky routing annotations | dynamic decision data, never long-term dashboard history |
| OpenTelemetry metrics      | user-owned long-term provider latency, TTFT, throughput, error, saturation, and worker health dashboards      | exported telemetry, not queried by built-in dashboard    |

The built-in realtime dashboard should use Redis-compatible hot-state data
directly and mark every value with TTL, freshness, and source metadata.
User-owned long-term provider performance dashboards should use OpenTelemetry
metric histograms and metric backend rollups. Durable route and usage evidence
should be joined only when an API needs explainability, attribution, or cost.

Aggregation rules:

- costs use fixed-point durable units
- time buckets use the request terminal timestamp unless the endpoint declares
  another timestamp
- retries must not double-count usage events
- upstream attempts can be counted separately from terminal requests
- route failover metrics come from route attempt events
- budget remaining uses durable ledger buckets plus policy-specific hot counter
  annotation when available
- percentile latency should come from rollups or bounded event scans, not
  unbounded raw event queries
- built-in realtime provider status comes from hot-state health hints, circuit
  state, and recent route evidence
- user-owned provider latency, TTFT, throughput, and error-rate trends should
  come from OpenTelemetry metrics when metric labels are bounded and authorized
  for export
- hot-state-derived fields must include a freshness marker and must not be used
  for historical comparisons after their TTL

Freshness indicators are required for every dashboard response.

## Retention

Dashboard APIs must respect retention policy.

| Data Kind              | Dashboard Behavior After Retention                                    |
| ---------------------- | --------------------------------------------------------------------- |
| raw usage events       | event rows disappear or are archived                                  |
| ledger buckets         | aggregate cost and usage remain while policy requires reporting       |
| route decisions        | route diagnostics degrade to aggregate counters                       |
| provider health events | model/provider dashboards show retained rollups only                  |
| audit events           | retained according to audit policy, separate from dashboard retention |

If a requested range crosses retention boundaries, responses must mark partial
data and explain which data class is no longer available.

## Acceptance Gates

- Organization, project, project member, API key, service account, model alias,
  model target, and provider endpoint dashboards are specified.
- Usage events contain enough immutable attribution to answer member-in-project
  questions historically.
- Dashboard APIs have explicit action ids and resource scopes.
- Dashboard responses include freshness and partial-data indicators.
- Model observability exposes latency, TTFT, throughput, errors, failover,
  route filtering, usage confidence, and estimated cost.
- OpenTelemetry export configuration and exporter health APIs are specified
  separately from the built-in realtime dashboard.
- No dashboard leaks raw prompts, completions, credentials, or secret headers.
