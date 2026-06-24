# Dashboards, Usage Analytics, And Model Observability API

Status: design draft for review.

This spec defines read APIs for dashboards, usage analytics, and model
observability. These APIs are first-class gateway APIs. They are not UI-only
queries and they must use the same organization, project, membership, and
authorization model as protocol ingress and admin APIs.

## Goals

- Provide scoped dashboards for tenant operators, organizations, projects, and
  project members.
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

| Scope             | Typical Actor                        | Resource Boundary                                        |
| ----------------- | ------------------------------------ | -------------------------------------------------------- |
| tenant            | operator or tenant owner             | all organizations and projects in a tenant               |
| organization      | organization owner, admin, or viewer | one organization and its projects                        |
| project           | project admin, maintainer, or viewer | one project                                              |
| project member    | project member or project admin      | one user's usage inside one project                      |
| API key           | key owner, project admin, auditor    | one API key or service-owned credential                  |
| model alias       | organization/project model viewer    | one client-visible model alias                           |
| model target      | operator or provider admin           | one upstream model target                                |
| provider endpoint | operator or provider admin           | one upstream endpoint, account, region, or provider kind |

Project member usage is keyed by immutable `project_member_id` recorded on
usage events. If a user is removed from a project later, historical usage
remains attributable to the member record that existed at request time.

## Dashboard Families

| Family                  | Purpose                                                               |
| ----------------------- | --------------------------------------------------------------------- |
| overview                | request, token, cost, budget, and error summary by scope              |
| usage                   | usage and estimated cost broken down by member, project, key, model   |
| model observability     | latency, TTFT, throughput, errors, usage confidence, and routing      |
| provider observability  | provider endpoint health, failover, retry, throttling, and credential |
| budget and quota        | spend, remaining budget, burn rate, hard blocks, rate-limit pressure  |
| route diagnostics       | filtered targets, selected targets, failover, sticky routing impact   |
| notification operations | outbox backlog, delivery success, retry, disabled sinks               |

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

## Overview Dashboard API

Example endpoints:

| Endpoint                                        | Scope                      |
| ----------------------------------------------- | -------------------------- |
| `GET /admin/v1/dashboards/tenant/overview`      | tenant operator            |
| `GET /admin/v1/dashboards/organizations/{id}`   | organization overview      |
| `GET /admin/v1/dashboards/projects/{id}`        | project overview           |
| `GET /admin/v1/dashboards/project-members/{id}` | one member's project usage |

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

| Endpoint                                                    | Purpose                                 |
| ----------------------------------------------------------- | --------------------------------------- |
| `GET /admin/v1/models/aliases/{id}/dashboard`               | alias-level latency, usage, errors      |
| `GET /admin/v1/models/targets/{id}/dashboard`               | upstream target latency, usage, errors  |
| `GET /admin/v1/models/aliases/{id}/routes`                  | selected routes, filtered targets       |
| `GET /admin/v1/models/aliases/{id}/quality`                 | usage confidence and provider error mix |
| `GET /admin/v1/provider-endpoints/{id}/model-observability` | endpoint/model health by target         |

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

| Endpoint                                            | Purpose                                      |
| --------------------------------------------------- | -------------------------------------------- |
| `GET /admin/v1/provider-endpoints/{id}/health`      | health windows, breaker state, recent errors |
| `GET /admin/v1/provider-endpoints/{id}/usage`       | usage and cost through one endpoint          |
| `GET /admin/v1/provider-endpoints/{id}/failover`    | failover in/out, error classes               |
| `GET /admin/v1/provider-endpoints/{id}/credentials` | masked credential status and rotation state  |

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

## Authorization

Dashboard APIs require explicit read actions.

| Action                                  | Resource                              |
| --------------------------------------- | ------------------------------------- |
| `gateway.dashboard.tenant.read`         | tenant dashboard scope                |
| `gateway.dashboard.organization.read`   | organization dashboard scope          |
| `gateway.dashboard.project.read`        | project dashboard scope               |
| `gateway.dashboard.project_member.read` | project member dashboard scope        |
| `gateway.usage.summary.read`            | usage aggregate scope                 |
| `gateway.usage.event.read`              | usage event rows                      |
| `gateway.model_observability.read`      | model alias or model target           |
| `gateway.provider_observability.read`   | provider endpoint operational metrics |
| `gateway.budget_dashboard.read`         | budget policy or budget scope         |

Authorization rules:

- tenant operators can read all dashboard scopes in the tenant
- organization owners/admins can read organization and project dashboards under
  their organization
- project admins can read their project dashboard and project member usage
- project members can read their own usage in a project when policy permits
- usage viewers can read aggregate usage for their assigned scope
- auditors can read event-level usage and route evidence according to redaction
  policy
- provider observability requires operator, provider admin, or security admin
  roles unless the response is explicitly redacted to organization/project
  level

## Aggregation And Freshness

Dashboard queries should read from durable usage events, ledger buckets, route
decision evidence, and metrics rollups. Runtime hot counters can annotate
near-real-time status, but they are not the durable dashboard source of truth.

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

- Organization, project, project member, API key, model alias, model target,
  and provider endpoint dashboards are specified.
- Usage events contain enough immutable attribution to answer member-in-project
  questions historically.
- Dashboard APIs have explicit action ids and resource scopes.
- Dashboard responses include freshness and partial-data indicators.
- Model observability exposes latency, TTFT, throughput, errors, failover,
  route filtering, usage confidence, and estimated cost.
- No dashboard leaks raw prompts, completions, credentials, or secret headers.
