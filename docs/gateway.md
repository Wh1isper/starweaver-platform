# LLM Gateway

The LLM gateway is a general-purpose model egress plane. It provides enterprise
model routing, upstream credential management, policy enforcement, budget
tracking, audit, and observability for outbound model traffic from applications,
services, automation, and any compatible HTTP model client.

## Core Responsibilities

- Authenticate inbound API keys and other caller credentials.
- Authorize model aliases, REST API actions, and resource scopes.
- Resolve routing groups, policies, provider endpoints, and upstream
  credentials.
- Enforce rate limits and budgets.
- Forward requests within compatible protocol families.
- Record usage, cost estimates, routing decisions, and audit evidence.
- Expose scoped dashboards for organizations, projects, project members, model
  aliases, and provider endpoints.
- Provide a Redis-compatible realtime operations dashboard and OpenTelemetry
  export configuration for operator-owned long-term monitoring dashboards.

## Protocol Families

The gateway routes within compatible protocol families. It may adapt URL,
authentication, provider-specific headers, model replacement, and stream
framing, but it should not promise arbitrary semantic conversion between
unrelated protocols.

Initial protocol families:

- OpenAI Responses.
- OpenAI Chat Completions.
- Anthropic Messages.
- Gemini.
- Bedrock Converse.

Provider-native routes are explicit extensions for operators that grant
`provider_native` access. They are not the default Bedrock protocol family.

## Enterprise Model

The gateway design is multi-tenant. Tenants contain organizations and projects.
Organizations receive explicit provider grants, and API keys receive scoped
access to model aliases and REST API actions. Administrators own upstream
provider credentials and route policies; callers never receive provider
secrets.

Organizations are the product-facing tenant boundary. Users have a default
organization, can be invited into other organizations, and receive project
membership inside an organization. Usage attribution is granular enough to
answer how much one person consumed in one project.

API keys are the public credential used by users, service accounts, and
automation. They can authenticate model traffic and authorized REST API calls.
The gateway should not expose a separate virtual-key product concept.

Routing groups are the main enterprise traffic unit. A routing group can hold
provider targets, weights, priorities, health filters, sticky routing policy,
budget pressure behavior, and failover limits. The gateway records route
decisions so operators can explain why a request used a provider or why a target
was filtered.

## Cost And Notifications

The gateway is an open-source cost and policy component, not a billing product.
It records provider usage, estimates provider cost, tracks budgets, and emits
integration events. Commercial operators can build their own billing systems by
consuming signed usage and budget notifications or by exporting usage events.

Upstream provider OAuth support is intentionally limited to Codex in the
initial design. Other providers use administrator-managed upstream credentials.
Human admin login is separate from upstream provider OAuth. Bare deployments can
start with local single-user mode, which is disabled by default and requires
both `STARWEAVER_GATEWAY_SINGLE_USER_USERNAME` and
`STARWEAVER_GATEWAY_SINGLE_USER_PASSWORD`. Login and session-read responses
include CSRF metadata for browser session mutations. Generic OIDC is the
standard external login path and supports issuer discovery, explicit pinned
endpoints, PKCE, nonce validation, token exchange, and JWKS-backed ID token
validation. GitHub OAuth App remains a convenience adapter for deployments that
want GitHub login without an OIDC broker.

## Detailed Specs

Architecture decisions live in the repository under `spec/gateway/`:

- `README.md` - gateway spec index and terminology.
- `00-requirements.md` - functional requirements and completion evidence.
- `01-llm-gateway.md` - product boundary and request lifecycle.
- `02-tenancy-access.md` - tenancy, RBAC, API keys, caller credentials, and
  provider grants.
- `03-provider-credential-catalog.md` - provider endpoints, upstream
  credentials, upstream Codex OAuth, model catalog, and pricing.
- `04-routing-router.md` - routing groups, route policy, health, failover, and
  route decisions.
- `05-runtime-protocol.md` - runtime protocol handling, provider adaptation,
  streaming, and usage extraction.
- `06-usage-cost-budget-notifications.md` - usage events, cost ledgers,
  budgets, quotas, webhooks, and exports.
- `07-admin-config-api.md` - admin resources, config snapshots, validation,
  audit, and route simulation.
- `08-security-observability-operations.md` - secret safety, redaction,
  telemetry, Redis-compatible hot state, OpenTelemetry export, storage,
  deployment, and incident operations.
- `09-validation-and-rollout.md` - phases, test matrices, compatibility, and
  review gates.
- `10-authorization-api-keys.md` - API keys, REST API permissions,
  authorization engine direction, action vocabulary, and policy gates.
- `11-login-user-management.md` - GitHub OAuth App login, OIDC login,
  sessions, invitations, default organizations, project membership, and user
  management.
- `12-dashboards-observability-api.md` - realtime operations dashboard,
  usage analytics, model observability, and project member consumption views.
