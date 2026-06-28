# UI/UX Review: Overview And Realtime Ops

Status: design draft for review.

## Module Purpose

Overview pages answer "how is this scope doing?" Realtime Ops answers "what is
happening now?" These pages must separate durable analytics from
Redis-compatible hot-state signals.

## Entry Points

- `/overview`
- `/overview/tenant`
- `/organizations/:organizationId/overview`
- `/projects/:projectId/overview`
- `/members/:projectMemberId/overview`
- `/realtime`
- `/realtime/providers`
- `/realtime/routes`
- `/realtime/budgets`
- `/realtime/quotas`
- `/realtime/workers`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `gateway_operator`
- `organization_admin`
- `project_admin`
- `project_viewer`
- `usage_viewer`

## Required Cards And Panels

Overview:

- request count, success, error, blocked, canceled
- token and media usage
- estimated provider cost
- budget remaining and burn rate
- latency and TTFT percentiles
- provider error rate and error classes
- usage confidence and missing usage count
- top projects, members, aliases, endpoints, keys, and service accounts

Realtime Ops:

- provider endpoint health, circuit, throttle, and drain posture
- recent route pressure and sticky routing annotations
- hot budget pressure and conservative-mode state
- live quota and concurrency pressure
- worker loaded config version and heartbeat
- config publication freshness and fallback explanation

## UX Decisions

- Overview pages use durable sources first. Realtime panels use hot state and
  must say so.
- Every metric row has source, freshness, and partial-data affordances.
- Hot-state panels show TTL, last update, policy/config version, and fallback.
- Operators can drill from realtime posture into durable route decisions when
  durable evidence exists.
- Empty realtime data is not a failure if hot state is intentionally disabled;
  show the fallback behavior.
- Do not show a green "healthy" state without source freshness.

## Data Dependencies

| API                                                  | Use                                    |
| ---------------------------------------------------- | -------------------------------------- |
| `/api/admin/v1/dashboards/tenant/overview`           | tenant overview                        |
| `/api/admin/v1/dashboards/organizations/{id}`        | organization overview                  |
| `/api/admin/v1/dashboards/projects/{id}`             | project overview                       |
| `/api/admin/v1/dashboards/project-members/{id}`      | member usage overview                  |
| `/api/admin/v1/dashboards/api-keys/{id}`             | API key overview                       |
| `/api/admin/v1/dashboards/service-accounts/{id}`     | service account overview               |
| `/api/admin/v1/realtime/overview`                    | realtime summary                       |
| future detailed `/api/admin/v1/realtime/*` endpoints | detailed realtime tabs beyond overview |

## Visualization Review

- Use compact metric groups, not oversized hero cards.
- Time series charts must have table equivalents or accessible summaries.
- Status panels use icon plus label plus timestamp.
- Error classes should be grouped and sortable.
- Provider and route pressure should support heatmap or stacked bar views only
  when labels remain bounded and readable.

## Empty, Loading, And Error States

| State                    | UX                                                                 |
| ------------------------ | ------------------------------------------------------------------ |
| no traffic               | show zero state with setup links to Models, Routing, and Providers |
| ledger lag               | mark partial data and show watermark                               |
| hot state stale          | show stale badge, TTL or expiry, and runtime fallback              |
| permission-limited scope | show redacted labels and explain authorization boundary            |
| query too wide           | prompt narrower range or export path                               |

## Redaction Review

- No prompts, completions, provider headers, request bodies, or raw secrets.
- Provider endpoint labels are redacted for actors without provider
  observability permission.
- Budget/cost values are hidden when the role lacks usage or budget read
  actions.

## Review Checklist

- All dashboard values display source and freshness.
- Hot-state values cannot be mistaken for durable history.
- Scope and time range are visible.
- Drilldowns preserve filters.
- Partial and unavailable data states are explicit.
- Realtime pages work when Redis-compatible hot state is unavailable.
- Detailed realtime tabs degrade to the overview endpoint until dedicated
  provider, route, budget, quota, and worker endpoints are added.
