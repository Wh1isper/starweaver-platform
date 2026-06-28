# UI/UX Review: Policy And Cost Controls

Status: design draft for review.

## Module Purpose

Policy pages manage provider grants, budget policies, quota policies, admission
policies, and redaction policies. They must make policy scope, deny closure,
stale-state behavior, and cache-loss behavior visible.

## Entry Points

- `/policy`
- `/policy/provider-grants`
- `/policy/provider-grants/:id`
- `/policy/budgets`
- `/policy/budgets/:id`
- `/policy/quotas`
- `/policy/quotas/:id`
- `/policy/admission`
- `/policy/redaction`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `security_admin`
- `organization_admin`
- `project_admin`
- `gateway_operator` for read-only operational posture
- `auditor` for policy history

## Required Workflows

- Grant or deny provider availability to an organization or project.
- Inspect grant closure over aliases, route policies, routing groups, targets,
  endpoints, and pricing SKUs.
- Create budget policies for tenant, organization, project, credential, alias,
  group, endpoint, or target scopes.
- Create quota and rate policies with cache-loss behavior.
- Show admission and redaction policy entries as phased surfaces until
  dedicated APIs are available.
- Simulate budget/quota pressure before publish.

## Data Dependencies

| API                                      | Use                                                  |
| ---------------------------------------- | ---------------------------------------------------- |
| `/api/admin/v1/provider-grants`          | list and create provider grants                      |
| `/api/admin/v1/provider-grants:validate` | grant validation                                     |
| `/api/admin/v1/provider-grants/{id}`     | grant detail and update                              |
| `/api/admin/v1/budget-policies`          | list and create budget policies                      |
| `/api/admin/v1/budget-policies:validate` | budget validation                                    |
| `/api/admin/v1/budget-policies/{id}`     | budget detail and update                             |
| `/api/admin/v1/quota-policies`           | list and create quota policies                       |
| `/api/admin/v1/quota-policies:validate`  | quota validation                                     |
| `/api/admin/v1/quota-policies/{id}`      | quota detail and update                              |
| future admission/redaction endpoints     | admission and redaction policy                       |
| `/api/admin/v1/realtime/overview`        | budget conservative-mode and quota pressure evidence |
| `/api/admin/v1/usage/*`                  | durable ledger source for budget and quota posture   |

## UX Decisions

- Provider grants show allow and deny in the same closure view.
- Deny rules must be visually stronger than allow rules.
- Budget pages use cost-control language, not billing language.
- Hard budget stale-state behavior is shown in the policy summary.
- Quota cache-loss behavior is shown next to the counter and window.
- Redaction policies use examples with safe placeholder payloads, never real
  prompt or secret material.

## Policy Summary Requirements

Provider grant summary:

- scope kind and id
- effect: allow or deny
- resource kind and id
- closure mode
- affected descendants
- validation warnings

Budget summary:

- scope kind and id
- period
- limit kind
- fixed-point amount and currency
- soft thresholds
- hard cap
- overage mode
- conservative consistency mode
- source/freshness for current spend

Quota summary:

- scope
- counter kind
- window
- limit
- increment source
- hot-state loss behavior
- fail-limited fallback bounds

## Empty, Loading, And Error States

| State                           | UX                                              |
| ------------------------------- | ----------------------------------------------- |
| no grants                       | show inherited or default provider availability |
| deny closure blocks all targets | blocking warning and simulation link            |
| budget rollup delayed           | show ledger lag and hot annotation if available |
| quota hot state unavailable     | show cache-loss mode and runtime behavior       |
| redaction policy invalid        | show fields that would leak sensitive data      |

## Redaction Review

- Policy previews never use real prompt, completion, header, or secret values.
- Redaction test examples must be synthetic.
- Audit diff displays policy changes safely.

## Review Checklist

- Users can tell exactly what scope a policy affects.
- Deny closure is visible before publish.
- Budget pages do not imply invoices or customer billing.
- Quota cache-loss behavior is explicit.
- Redaction examples are synthetic and safe.
