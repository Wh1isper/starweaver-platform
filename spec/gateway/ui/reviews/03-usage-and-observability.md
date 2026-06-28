# UI/UX Review: Usage And Observability

Status: design draft for review.

## Module Purpose

Usage and observability pages help users attribute model consumption, cost,
latency, routing behavior, provider health, and usage confidence across gateway
scopes without becoming a paid billing product.

## Entry Points

- `/usage`
- `/usage/summary`
- `/usage/timeseries`
- `/usage/events`
- `/usage/breakdowns/projects`
- `/usage/breakdowns/members`
- `/usage/breakdowns/models`
- `/usage/breakdowns/providers`
- `/models/aliases/:id/observability`
- `/models/targets/:id/observability`
- `/providers/endpoints/:id/observability`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `gateway_operator`
- `organization_admin`
- `project_admin`
- `project_developer`
- `project_viewer`
- `usage_viewer`
- `auditor`

## Required Workflows

- Compare usage and cost across projects in an organization.
- Answer "what did this person consume in this project?"
- Inspect usage by API key or service account.
- Inspect latency, TTFT, throughput, errors, failover, and filtered candidates
  for a model alias.
- Inspect provider endpoint usage and health without exposing credentials.
- Export usage rows when the actor is authorized.

## Data Dependencies

| API                                                         | Use                  |
| ----------------------------------------------------------- | -------------------- |
| `/api/admin/v1/usage/summary`                               | aggregate usage      |
| `/api/admin/v1/usage/timeseries`                            | time series          |
| `/api/admin/v1/usage/breakdown/by-project`                  | project ranking      |
| `/api/admin/v1/usage/breakdown/by-project-member`           | member consumption   |
| `/api/admin/v1/usage/breakdown/by-model`                    | model usage          |
| `/api/admin/v1/usage/breakdown/by-provider-endpoint`        | provider usage       |
| `/api/admin/v1/usage/events`                                | paginated usage rows |
| `/api/admin/v1/models/aliases/{id}/dashboard`               | alias observability  |
| `/api/admin/v1/models/targets/{id}/dashboard`               | target observability |
| `/api/admin/v1/provider-endpoints/{id}/observability/usage` | provider usage       |

These endpoints are backend-ready as of the 2026-06-28 review. UI work should
not treat usage analytics as speculative.

## UX Decisions

- Usage is provider cost and policy evidence, not commercial billing.
- Cost values must show currency, fixed-point display policy, pricing version
  when relevant, and confidence.
- Missing usage is a first-class signal, not silently zero.
- Project member usage uses immutable `project_member_id` for historical
  attribution.
- Event rows are cursor-paginated and never unbounded.
- Latency percentiles should show sample size and data freshness.

## Table And Chart Review

- Tables default to columns that answer the page's question.
- Advanced dimensions live in column visibility and grouping controls.
- Charts use bounded label counts. Large breakdowns use tables first.
- Time granularity is explicit and validated against the selected range.
- Export buttons explain retention and redaction behavior before starting.

## Empty, Loading, And Error States

| State                      | UX                                               |
| -------------------------- | ------------------------------------------------ |
| no usage                   | show no traffic for selected scope and range     |
| usage confidence missing   | show missing or estimated count and reason class |
| pricing unavailable        | mark cost as unpriced, not zero                  |
| retention boundary crossed | mark partial data and show retained classes      |
| query rejected             | show range or granularity correction             |

## Redaction Review

- Usage rows show ids, scope, status, usage counts, cost, route ids, and
  confidence.
- Usage rows never show raw prompt text, completion text, provider request
  bodies, provider response chunks, or secret headers.
- Provider names may be redacted when actor lacks provider observability.

## Review Checklist

- Member-in-project attribution is understandable.
- Usage confidence is visible in summary and rows.
- Costs are clearly provider estimates, not invoices.
- Large scans require export or narrower filters.
- Provider observability redaction matches role.
- Export initiation is audited and scoped.
