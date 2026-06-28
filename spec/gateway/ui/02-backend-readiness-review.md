# Gateway UI Backend Readiness Review

Status: design review for implementation alignment.

Review date: 2026-06-28.

This review maps the current gateway backend implementation to the UI specs.
It is based on `crates/starweaver-gateway/src/service.rs`,
`crates/starweaver-gateway/src/route.rs`, `Makefile`,
`.github/workflows/images.yml`, `crates/starweaver-gateway/Dockerfile`, and
`spec/gateway/memos/2026-06-24-implementation-plan.md`.

## Summary

The backend has enough implemented surface for the admin console spec to move
from conceptual design to integration planning for most implemented gateway
modules. The main delivery blocker is not API capability. It is web asset
delivery: the gateway server does not yet serve compiled web assets or SPA
fallback routes. The external `/api` mount is implemented for auth, admin,
dashboard, evidence, and model ingress APIs, with generated OpenAPI available
at `/api/openapi.json`.

## Backend-Ready UI Surfaces

| UI module                 | Backend readiness                                                                                                                                                                                                                                                                                                                                      |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| App shell and auth        | Ready after `/api` mount. Backend has single-user login, generic OIDC provider discovery/start/callback, session read, logout, default/active org/project updates, invitation preview/accept, and CSRF metadata.                                                                                                                                       |
| Overview and realtime ops | Ready for overview. Backend has realtime overview plus tenant, organization, project, project member, API key, service account, model alias, model target, and provider endpoint overview/observability routes. Detailed realtime subpages still need dedicated endpoints.                                                                             |
| Usage and observability   | Ready. Backend has usage summary, timeseries, event rows, project/member/model/provider breakdowns, durable ledger-backed dashboard measures, model dashboards, target dashboards, and provider endpoint usage observability.                                                                                                                          |
| Model catalog             | Ready for aliases, targets, pricing SKUs. Catalog import remains future.                                                                                                                                                                                                                                                                               |
| Routing                   | Ready for routing groups, routing group targets, route policies, and route simulation.                                                                                                                                                                                                                                                                 |
| Providers and credentials | Ready. Backend has provider endpoints, upstream credentials, secret refs, strong-auth secret locator reads, Codex OAuth connections/sessions/revoke/refresh-status, and redaction behavior.                                                                                                                                                            |
| Access and identity       | Ready for the planned access flows. Backend has organizations, projects, memberships, project-member create, invitations, users, user sessions, external identities, identity providers, service accounts, API key create/list/get/rotate/disable with one-time raw key return, local single-user, generic OIDC, and CSRF-protected session mutations. |
| Policy and cost controls  | Ready for provider grants, budgets, quotas, runtime budget/quota enforcement evidence, and conservative-mode dashboard state. Admission and redaction policy admin endpoints remain future.                                                                                                                                                            |
| Evidence and audit        | Ready for route decision list/detail, route attempt list/detail, usage events, audit event list, export jobs, and manifests.                                                                                                                                                                                                                           |
| Operations and delivery   | Ready for config snapshots, validation diagnostics, publish, rollback, OTel export config, notification sinks/subscriptions/outbox replay, export jobs, emergency operations, production profile gates, Docker image smoke, compose smoke, restore rehearsal, and `/api` external mount. Web asset serving remains Phase 0 work.                       |

## Route Prefix Readiness

Current backend route metadata keeps canonical internal root patterns:

- `/auth/v1/*`
- `/admin/v1/*`
- `/v1/*`
- `/v1beta/*`
- `/model/*`
- `/native/*`

The implemented external browser and model-client paths are mounted under
`/api`:

- `/api/auth/v1/*`
- `/api/admin/v1/*`
- `/api/v1/*`
- `/api/v1beta/*`
- `/api/model/*`
- `/api/native/*`

Phase 0 must preserve the existing authorization and audit metadata while
adding web asset serving and SPA fallback. Unknown `/api/*` paths already return
JSON API errors and must not be intercepted by the SPA fallback.

## Implemented Endpoint Families For UI Planning

Auth/session:

- `GET /auth/v1/providers`
- `POST /auth/v1/single-user/login`
- `GET /auth/v1/session`
- `POST /auth/v1/session/default-organization`
- `POST /auth/v1/session/active-organization`
- `POST /auth/v1/session/active-project`
- `POST /auth/v1/logout`
- `GET /auth/v1/invitations/{token}/preview`
- `POST /auth/v1/invitations/{token}/accept`
- `GET /auth/v1/providers/{login_provider_id}`
- `GET /auth/v1/providers/{login_provider_id}/login`
- `POST /auth/v1/providers/{login_provider_id}/callback`

Admin and configuration:

- config snapshots, validation diagnostics, publish, rollback
- route simulations
- route decisions and route attempts
- organizations, projects, organization members, project members
- organization invitations
- users, user sessions, external identities
- identity providers
- service accounts
- provider endpoints, upstream credentials, secret refs
- Codex OAuth connections, sessions, revoke, refresh status
- model targets, model aliases, pricing SKUs
- routing groups, routing group targets, route policies
- provider grants, budget policies, quota policies
- OpenTelemetry export configs
- notification sinks, subscriptions, outbox replay
- usage summary, timeseries, events, and breakdowns
- audit event list
- export jobs and manifests
- emergency operation list/read and emergency mutation routes

## Remaining Backend Gaps For UI

These UI specs must remain explicitly blocked or phased:

- server-owned web static asset serving and SPA fallback
- web build, lint, test, and Docker asset packaging gates
- catalog import endpoints
- admission policy endpoints
- redaction policy endpoints
- maintenance window endpoints
- detailed realtime sub-endpoints beyond overview

## Readiness Requirements Before UI Implementation Exits Phase 0

- Gateway binary serves the compiled web app from `/`.
- Release Docker image contains compiled web assets and does not require Node at
  runtime.
- Browser code calls only `/api/...` APIs.
- Root-level API routes are either not externally exposed or documented as
  temporary compatibility aliases.
- Docker smoke verifies `/`, one static asset, `/api/admin/v1/realtime/overview`
  as JSON, `/api/does-not-exist` as JSON error, and `/healthz`.
- `make ci` includes web install, lint, typecheck, tests, build, and existing
  gateway harnesses.
