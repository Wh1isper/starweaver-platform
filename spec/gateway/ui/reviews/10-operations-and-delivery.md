# UI/UX Review: Operations And Delivery

Status: design draft for review.

## Module Purpose

Operations pages manage config snapshots, validation diagnostics, publication,
rollback, OpenTelemetry export configuration, notification sinks, maintenance
windows, emergency operations, and delivery posture. This module also reviews
the server-owned web delivery model.

## Entry Points

- `/operations`
- `/operations/config`
- `/operations/config/snapshots`
- `/operations/config/validation`
- `/operations/otel-export`
- `/operations/notifications`
- `/operations/maintenance`
- `/operations/emergency`
- `/operations/delivery`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `gateway_operator`
- `security_admin`
- `auditor` for read-only evidence

## Required Workflows

- Validate current or draft configuration.
- Publish a config snapshot.
- Roll back to a prior valid snapshot.
- Inspect worker convergence and loaded config versions.
- Create and validate OpenTelemetry exporter configuration.
- Create notification sinks and subscriptions.
- Inspect delivery attempts and retry state.
- Keep maintenance windows hidden or disabled until dedicated endpoints exist.
- Run emergency operations such as disable credential, disable endpoint, freeze
  config, force budget block, drain routing group, and rollback snapshot.
- Verify Docker image and static web serving posture.

## Data Dependencies

| API                                                         | Use                           |
| ----------------------------------------------------------- | ----------------------------- |
| `/api/admin/v1/config/snapshots`                            | list snapshots                |
| `/api/admin/v1/config/snapshots/{id}`                       | snapshot detail               |
| `/api/admin/v1/config/snapshots:validate`                   | validation                    |
| `/api/admin/v1/config/snapshots:publish`                    | publish                       |
| `/api/admin/v1/config/snapshots:rollback`                   | rollback                      |
| `/api/admin/v1/config/validation-diagnostics`               | diagnostics                   |
| `/api/admin/v1/observability/otel-export/configs`           | OTel configs                  |
| `/api/admin/v1/notification/sinks`                          | notification sinks            |
| `/api/admin/v1/notification/sinks/{id}/subscriptions`       | notification subscriptions    |
| `/api/admin/v1/notification/outbox/{id}/replay`             | strong-auth outbox replay     |
| `/api/admin/v1/exports/jobs`                                | export jobs                   |
| `/api/admin/v1/exports/jobs/{id}/manifest`                  | export manifests              |
| `/api/admin/v1/emergency/operations`                        | emergency operation list      |
| `/api/admin/v1/emergency/operations/{id}`                   | emergency operation detail    |
| `/api/admin/v1/emergency/upstream-credentials/{id}/disable` | emergency credential disable  |
| `/api/admin/v1/emergency/provider-endpoints/{id}/disable`   | emergency endpoint disable    |
| `/api/admin/v1/emergency/routing-groups/{id}/drain`         | emergency routing group drain |
| `/api/admin/v1/emergency/config/freeze`                     | emergency config freeze       |
| `/api/admin/v1/emergency/config/snapshots/{id}/rollback`    | emergency snapshot rollback   |
| `/api/admin/v1/emergency/budget-policies/{id}/force-block`  | emergency budget block        |
| future maintenance endpoints                                | maintenance windows           |

## UX Decisions

- Config snapshots are immutable and versioned.
- Publish and rollback are high-risk operations requiring reason capture,
  expected version, and strong-auth when the API requires it.
- Validation diagnostics separate blocking errors from warnings.
- Publication convergence shows worker version, heartbeat, source, and
  fallback state.
- OTel exporter failures degrade user-owned dashboards only and must not appear
  as gateway request-path failures.
- Emergency operations are time-bounded where possible and show rollback path.

## Delivery Review

The delivery page or operator diagnostics should make the serving model clear:

- gateway server serves web app at `/`
- APIs are mounted under `/api`, with canonical route metadata preserved in
  OpenAPI extensions
- root-level probes are available
- static asset version and build revision are visible
- gateway binary version and git revision are visible
- Docker image labels include source and revision
- web asset missing state is explicit

## Emergency Action Review

Each emergency action dialog must show:

- operation type
- affected scope and resources
- reason text area
- expiry or rollback condition when supported
- expected version or snapshot id
- strong-auth prompt when required
- alert/audit impact
- confirmation using the resource name or id

## Empty, Loading, And Error States

| State                 | UX                                                           |
| --------------------- | ------------------------------------------------------------ |
| no snapshots          | show bootstrap validation state                              |
| validation running    | show progress and resources being checked                    |
| publish rejected      | show blocking diagnostics and affected resources             |
| worker stale          | show loaded version, latest version, heartbeat, and fallback |
| OTel exporter failing | show failure count, last success, dropped metric count       |
| notification backlog  | show retry schedule and disable state                        |

## Redaction Review

- OTel headers and notification signing secrets are write-only.
- Notification URLs redact embedded credentials.
- Validation diagnostics must not include raw secret material.
- Emergency audit diffs show safe metadata only.

## Review Checklist

- Publish and rollback cannot be mistaken for ordinary saves.
- Validation diagnostics are actionable.
- Worker convergence is visible.
- OTel and notification failures are scoped correctly.
- Delivery model proves `/` web and `/api` API separation.
- Emergency operations require reason and produce audit evidence.
- Maintenance windows are not shown as implemented until their endpoints exist.
