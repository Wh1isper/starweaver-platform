# UI/UX Review: Providers And Credentials

Status: design draft for review.

## Module Purpose

Provider pages manage upstream provider endpoints, upstream credentials, secret
refs, Codex OAuth connections, and credential rotation. The UI must strictly
separate provider endpoint metadata from secret-bearing credential state.

## Entry Points

- `/providers`
- `/providers/endpoints`
- `/providers/endpoints/:id`
- `/providers/credentials`
- `/providers/credentials/:id`
- `/providers/secret-refs`
- `/providers/codex-oauth`
- `/providers/rotation`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `security_admin`
- `gateway_operator` for operational read and drain
- `auditor` for redacted history

## Required Workflows

- Create and validate a provider endpoint.
- Create or rotate an upstream credential through a dedicated secret write
  path.
- Link provider endpoint to credential.
- Inspect credential status without reading secret material.
- Inspect SecretRef metadata and, for strong-auth security admins, raw locator
  metadata without exposing secret values.
- Drain, disable, or mark provider endpoint degraded.
- Configure Codex upstream OAuth connection and inspect refresh state.
- Review credential rotation history and safe audit diff.

## Data Dependencies

| API                                                               | Use                                      |
| ----------------------------------------------------------------- | ---------------------------------------- |
| `/api/admin/v1/provider-endpoints`                                | list and create endpoints                |
| `/api/admin/v1/provider-endpoints:validate`                       | endpoint validation                      |
| `/api/admin/v1/provider-endpoints/{id}`                           | endpoint detail and status               |
| `/api/admin/v1/upstream-credentials`                              | list and create credentials              |
| `/api/admin/v1/upstream-credentials:validate`                     | credential validation                    |
| `/api/admin/v1/upstream-credentials/{id}`                         | credential detail and update             |
| `/api/admin/v1/secret-refs`                                       | list and create secret refs              |
| `/api/admin/v1/secret-refs/{id}`                                  | secret ref detail                        |
| `/api/admin/v1/secret-refs/{id}/locator`                          | strong-auth raw locator metadata         |
| `/api/admin/v1/codex/oauth/connections`                           | list and create Codex OAuth connections  |
| `/api/admin/v1/codex/oauth/connections/{id}`                      | Codex OAuth connection detail and status |
| `/api/admin/v1/codex/oauth/connections/{id}/sessions`             | list and start Codex OAuth sessions      |
| `/api/admin/v1/codex/oauth/sessions/{id}`                         | Codex OAuth session detail               |
| `/api/admin/v1/codex/oauth/sessions/{id}/revoke`                  | revoke Codex OAuth session               |
| `/api/admin/v1/codex/oauth/refresh-status/{id}`                   | refresh status                           |
| `/api/admin/v1/provider-endpoints/{id}/observability/credentials` | masked credential health                 |

## UX Decisions

- Provider endpoint forms never contain raw secret values.
- Credential create and rotation flows use a dedicated secret step with clear
  one-way write semantics.
- Read pages show `secret_ref_id`, kind, locator mask, version hint,
  fingerprint, expiry, status, and last safe error.
- Endpoint status is operational: active, disabled, draining, degraded, deleted.
- Credential status is security/auth state: active, disabled, rotating,
  expired, error.
- Codex OAuth is presented as the only v1 upstream OAuth provider.
- Codex OAuth lifecycle routes require strong auth and deny API-key access.

## Form Review

Provider endpoint:

- provider kind
- protocol families
- upstream base URL
- region
- cloud account ref
- credential reference
- compliance labels
- cost labels
- status
- validation diagnostics

Upstream credential:

- credential kind
- secret ref or raw secret write
- allowed endpoint/provider scope
- expiry
- rotation policy
- verification target
- validation diagnostics

## Empty, Loading, And Error States

| State                | UX                                                           |
| -------------------- | ------------------------------------------------------------ |
| no providers         | prompt endpoint setup and clarify credential separation      |
| credential expired   | show affected endpoints and rotate action                    |
| secret fetch error   | show safe error code and affected routing posture            |
| endpoint degraded    | show route policy eligibility impact                         |
| OAuth refresh failed | show safe refresh status, last attempt, and reconnect action |

## Redaction Review

- Never render raw secret values.
- Never put raw secret values into client logs, error details, analytics, or
  local storage.
- Clipboard actions for credentials copy only safe ids or masks.
- Audit diff for rotation shows version and fingerprint changed, not secret.

## Review Checklist

- Endpoint and credential concepts are clearly separated.
- Raw secret values are write-only.
- Rotation state and rollback window are understandable.
- Disable, drain, and degraded states have distinct UI.
- Provider observability does not leak credential details to unauthorized roles.
- Codex OAuth pages show token secret refs only as masked metadata.
