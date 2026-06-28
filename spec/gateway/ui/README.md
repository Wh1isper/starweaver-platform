# Gateway UI Specs

Status: design draft for review.

This directory defines the gateway admin console as the web control plane for
the Starweaver gateway. The console is served by the gateway server itself. The
root path serves the web app, while gateway APIs are mounted under `/api`.

## Design Position

The gateway UI is an enterprise control plane, not a marketing surface and not
a separate application runtime. It helps authorized users operate model egress,
configure gateway resources, govern access, inspect evidence, and manage
cost-control posture.

The UI must not introduce new resource semantics. It is a browser client over
the same admin, auth, dashboard, evidence, and model ingress APIs used by CLI,
Terraform-style automation, service integrations, and compatible model
clients.

## File Map

| File                                      | Scope                                                                                                           |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `00-admin-console-spec.md`                | Product, IA, UX, visual direction, and frontend architecture                                                    |
| `01-implementation-plan.md`               | Implementation sequence, beginning with CI, image, and server-owned web delivery                                |
| `02-backend-readiness-review.md`          | Current backend-to-UI readiness review for implemented gateway surfaces                                         |
| `reviews/01-app-shell-and-navigation.md`  | App shell, workspace context, navigation, command/search, and responsive behavior                               |
| `reviews/02-overview-realtime-ops.md`     | Overview and Redis-compatible realtime operations dashboards                                                    |
| `reviews/03-usage-and-observability.md`   | Usage analytics, model observability, provider observability, and freshness UX                                  |
| `reviews/04-model-catalog.md`             | Model aliases, model targets, pricing SKUs, and catalog import flows                                            |
| `reviews/05-routing-and-simulation.md`    | Routing groups, route policies, simulation, failover, sticky, drain, and canary UX                              |
| `reviews/06-providers-and-credentials.md` | Provider endpoints, upstream credentials, secret refs, Codex OAuth, and rotation                                |
| `reviews/07-access-and-identity.md`       | Organizations, projects, users, memberships, invitations, API keys, and service accounts                        |
| `reviews/08-policy-and-cost-controls.md`  | Provider grants, budgets, quotas, admission policy, and redaction policy                                        |
| `reviews/09-evidence-and-audit.md`        | Usage events, route decisions, attempt events, audit events, exports, and redacted diffs                        |
| `reviews/10-operations-and-delivery.md`   | Config snapshots, validation, publish, rollback, OTel export, notifications, maintenance, and emergency actions |

## Source Specs

The UI spec depends on these gateway specs:

- `../00-requirements.md`
- `../02-tenancy-access.md`
- `../03-provider-credential-catalog.md`
- `../04-routing-router.md`
- `../06-usage-cost-budget-notifications.md`
- `../07-admin-config-api.md`
- `../08-security-observability-operations.md`
- `../10-authorization-api-keys.md`
- `../11-login-user-management.md`
- `../12-dashboards-observability-api.md`

## Delivery Rules

- The gateway server owns web serving for the default deployment.
- Browser routes are served from `/` with SPA fallback for non-API paths.
- Gateway JSON, auth, admin, dashboard, evidence, and protocol APIs should be
  exposed externally under `/api` for the web-console delivery shape. The
  backend now serves the generated external OpenAPI contract at
  `/api/openapi.json` and keeps canonical route metadata aligned through
  operation extensions.
- Health and readiness probe paths may remain root-level and may also be
  mirrored under `/api/system`.
- The release Docker image includes the compiled web assets and the gateway
  binary.
- The UI must preserve gateway redaction rules and must never expose prompt
  bodies, completion bodies, API key values, upstream secrets, OAuth tokens, or
  raw secret locators.
