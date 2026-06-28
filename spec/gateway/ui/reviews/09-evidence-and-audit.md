# UI/UX Review: Evidence And Audit

Status: design draft for review.

## Module Purpose

Evidence pages expose route decisions, route attempts, usage events, audit
events, redacted diffs, and exports. They must support debugging, compliance,
and operational review without leaking sensitive payloads or secrets.

## Entry Points

- `/evidence`
- `/evidence/routes`
- `/evidence/routes/:id`
- `/evidence/attempts`
- `/evidence/usage-events`
- `/evidence/audit-events`
- `/evidence/audit-events/:id`
- `/evidence/exports`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `gateway_operator`
- `security_admin`
- `usage_viewer`
- `auditor`
- scoped organization/project admins where policy permits

## Required Workflows

- Search route decisions by request id, trace id, alias, project, endpoint,
  status, or time range.
- Inspect selected target, final target, failover, and filtered reason counts.
- Inspect attempt events and provider error classes.
- Inspect usage event attribution, pricing version, confidence, and cost.
- Inspect audit event actor context and redacted diff through the implemented
  audit event list.
- Start or inspect export jobs and manifests.

## Data Dependencies

| API                                        | Use                             |
| ------------------------------------------ | ------------------------------- |
| `/api/admin/v1/route-decisions`            | dedicated route evidence list   |
| `/api/admin/v1/route-decisions/{id}`       | dedicated route decision detail |
| `/api/admin/v1/route-attempts`             | dedicated attempt event rows    |
| `/api/admin/v1/usage/events`               | usage event rows                |
| `/api/admin/v1/audit/events`               | audit event list                |
| `/api/admin/v1/exports/jobs`               | export job list and create      |
| `/api/admin/v1/exports/jobs/{id}`          | export job metadata             |
| `/api/admin/v1/exports/jobs/{id}/manifest` | redacted export manifest        |

## UX Decisions

- Evidence pages are table-first with detail inspector side panels.
- Every row includes request id or trace id when available.
- Redacted fields are explicitly marked as redacted, not missing.
- Copy actions should prefer stable ids and safe JSON snippets.
- Export flows show retention, redaction, scope, and expected row count when
  available.
- Audit events show actor context captured at request time, not current user
  profile state inferred later.

## Route Decision Detail

The detail page should show:

- request id and trace id
- actor and credential metadata
- scope: tenant, organization, project
- model alias and protocol family
- route policy and policy snapshot hash
- selected and final group/target/endpoint when authorized
- budget and quota posture
- filtered counts and reasons
- attempt timeline
- terminal status and error class
- related usage event and audit events

## Audit Event Detail

The detail page should show:

- event type
- actor context
- resource kind and id
- scope kind and id
- before and after versions
- redacted diff
- idempotency key when safe
- request id and trace id
- created timestamp
- related config snapshot version

## Empty, Loading, And Error States

| State                       | UX                                            |
| --------------------------- | --------------------------------------------- |
| no evidence                 | show selected filter range and explain source |
| retained aggregate only     | show retention boundary and available rollups |
| redacted provider labels    | show authorization reason when safe           |
| export too large            | require narrower range or async export        |
| missing related usage event | show usage confidence or ingestion lag        |

## Redaction Review

- No prompts, completions, provider request bodies, provider response chunks,
  raw headers, API key values, upstream secrets, OAuth tokens, or raw secret
  locators.
- Redacted diff must never show raw secret values.
- Provider metadata visibility follows provider observability authorization.

## Review Checklist

- Route decisions explain selection and exclusion.
- Evidence rows are cursor-paginated.
- Audit event actor context is immutable.
- Redacted fields are clear and safe.
- Export flows are scoped, redacted, and audited.
- Route-decision and attempt pages use the dedicated evidence endpoints and
  keep dashboard drilldowns filter-compatible.
