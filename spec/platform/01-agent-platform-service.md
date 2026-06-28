# Agent Platform Service

Status: discussion draft.

The agent platform service is the agent control plane for hosted Starweaver
deployments. It owns conversations, runs, sessions, approvals, environment
attachments, stream replay, and durable execution evidence.

This document complements `../01-platform-service.md`, which contains the
detailed hosted platform service candidate. This file focuses on the relationship
between the agent platform service and the LLM gateway in the shared service
workspace.

## Goals

- Expose service APIs for creating and managing agent runs.
- Persist run, session, approval, and deferred-tool metadata.
- Archive large ordered evidence such as raw run events, display messages,
  message history snapshots, and replay snapshots.
- Attach environments through provider-neutral host contracts.
- Use the LLM gateway as a model egress option without depending on gateway
  internals.

## Non-Goals

- Do not replace the Starweaver runtime engine.
- Do not embed gateway routing logic.
- Do not own upstream provider credentials directly when the gateway is the
  configured model egress path.
- Do not make platform HTTP resources part of the SDK/runtime crate boundary.

## Relationship To Gateway

The platform service may route model traffic through the gateway by default.
That is a deployment topology, not a crate dependency.

```mermaid
flowchart TD
    client[Client]
    platform[Agent platform service]
    run[Run coordinator]
    gateway[LLM gateway]
    env[Environment attachments]
    archive[Stream and evidence archive]

    client --> platform
    platform --> run
    run --> gateway
    run --> env
    run --> archive
```

The run coordinator should pass context to the gateway through versioned HTTP
headers or request metadata:

- tenant id
- project id
- request id
- trace context
- run id
- conversation or session affinity key
- desired model alias
- budget or policy hint when allowed

The gateway returns model responses, stream chunks, usage metadata, and gateway
decision metadata. The platform records run evidence but does not need to know
which upstream credential or provider endpoint was selected.

## Shared Auth And Permissions

The platform is expected to share some authn/authz foundations with the
gateway, but not by depending on gateway internals. The first implementation
should keep platform authorization service-local while it proves concrete
resource semantics for runs, conversations, agents, approvals, environments, and
evidence archives.

Candidate shared layers should be evaluated after both services have concrete
use cases:

- stable contracts for ids, actor context, tenant/organization/project scope,
  principal references, sessions, service accounts, error envelopes, and audit
  context
- identity domain behavior for login providers, users, external identities,
  sessions, memberships, role bindings, and action grants
- policy helpers for action/resource registries, Cedar schema generation,
  built-in role templates, and validation fixtures

Gateway model permissions and platform run/environment permissions must remain
service-specific namespaces. A shared policy engine is acceptable only if it
preserves those namespaces and contract tests prove neither service can widen
the other's permissions.

Initial platform-local authorization foundation:

- platform actions use the `platform.*` namespace and do not reuse gateway action
  ids
- resource kinds cover conversations, agent sessions, runs, run events,
  approvals, deferred tools, environment attachments, and evidence archives
- built-in roles are scoped to tenant, organization, or project boundaries
- organization-scoped grants can authorize descendant project resources
- project-scoped grants cannot cross project ids
- service account actors can create and read automation resources but cannot use
  user-only actions such as approval decisions or run steering
- item-level filtering must use the same authorization engine as route handlers

The foundation HTTP implementation maps every platform route to a stable action
and resource kind before handlers read or mutate run metadata.

Foundation route metadata should cover:

- conversation create/read and conversation session list routes
- run create/read/cancel/steer/event routes
- approval decision routes
- deferred tool list/resume routes
- environment attachment create/list/health/release routes
- evidence archive read and privileged debug-read routes

Route metadata is the source of truth for handler authorization. Handler code
looks up metadata first, resolves the resource owner from storage, then calls
the platform-local authorization engine.

Storage ownership foundations should keep authorization ownership separate from
handler business logic:

- every resource owner record stores resource kind, resource id, tenant id,
  optional organization id, and optional project id
- project-scoped records require an organization id
- the ownership key includes both resource kind and resource id so different
  resource types can safely reuse ids
- owner records convert directly into authorization resource references
- handlers resolve ownership before reading detailed run, approval,
  environment, or evidence records
- cross-project access must be denied from resolved owner metadata, not from
  caller-provided path or header scope
- business resource records store safe typed projections separately from
  authorization ownership records
- handlers read business projections only after bearer session authentication,
  route metadata resolution, owner lookup, and authorization succeed

Foundation HTTP handler tests currently prove:

- opaque bearer session, API key, and service-token authentication resolve an
  `AuthenticatedActor` before route authorization
- session tokens, API keys, and service tokens are stored by hash, not raw token
  value
- run read authorization succeeds through route metadata and resolved owner
  metadata
- conversation read and run cancel return safe business resource projections
  after authorization
- API key credentials can authorize read handlers through the same ownership and
  grant path as user sessions
- cross-project run read is denied from resolved owner metadata
- approval decisions require a human user actor even when a service account has
  broad grants
- service-token credentials resolve to service-account actors and cannot use
  user-only actions
- approval decisions by a user return safe approval metadata after
  authorization
- environment attachment health reads use the attachment lease owner
- evidence archive reads use evidence archive owner metadata
- missing resource owners return `404` before detailed business records are read
- missing business records return `404` after owner authorization succeeds
- missing bearer session authentication returns `401`
- a revoked session token fails closed and does not fall back to an API key or
  service token with the same raw bearer value
- colon action paths such as `/v1/runs/{run_id}:cancel` are parsed through the
  route metadata matcher

The foundation handler accepts `Authorization: Bearer ...` credentials and
resolves actors through platform-local session, API key, and service-token
stores. The current in-memory stores are foundation adapters; production
entrypoints must back the same actor-resolution contract with durable sessions,
API keys, service tokens, or mTLS credentials before exposure.

The first durable platform schema foundation is now service-local and additive.
It establishes:

- tenant, organization, project, principal, user, service-account, membership,
  role-binding, and action-grant tables
- identity-provider and external-identity tables where generic OIDC is the
  standard login provider shape and single-user mode remains an explicit
  bootstrap mode
- OIDC login-attempt storage that persists state, nonce, and PKCE verifier
  hashes only, with status and expiry metadata for callback replay protection
- organization invitation storage that persists invitation-token hashes only,
  supports principal or email targets, and records pending, accepted, revoked,
  and expired lifecycle metadata
- auth-session and bearer-credential tables that store token hashes, visible
  prefixes, status, expiration, revocation, and actor scope, but never raw
  bearer values
- mTLS identity tables that map verified client certificate subjects or SPIFFE
  ids to scoped platform actors
- resource-owner rows keyed by `(resource_kind, resource_id)` with tenant,
  organization, and project scope
- safe business tables for conversations, agent sessions, runs, run events,
  approvals, deferred tools, environment attachments, evidence archives, and
  idempotency keys

The first PostgreSQL repository adapter is also service-local. It provides typed
async methods for:

- recording and resolving auth sessions by bearer-token hash
- recording and resolving API key or service-token bearer credentials by
  token hash
- recording and resolving verified mTLS subjects
- recording OIDC login attempts and loading them by hashed OAuth state
- completing verified OIDC logins in one transaction that consumes the attempt,
  repairs the local user default organization/project, links the external
  identity without cross-principal reassignment, grants the user organization
  admin on the default organization, and records the issued session hash
- listing organization and project memberships, loading memberships by stable
  id, updating membership status with optimistic concurrency, and cascading
  inactive organization membership status to child project memberships
- creating, listing, loading, revoking, and accepting organization invitations;
  accept updates the invitation and upserts organization/project memberships in
  one PostgreSQL transaction
- recording and loading resource ownership by `(resource_kind, resource_id)`
- recording safe business-resource projections with their owner metadata in one
  transaction
- loading safe business-resource projections only after owner metadata is
  present

The foundation HTTP service state has an explicit repository backend profile:

- `in_memory` keeps the deterministic foundation stores for unit tests and
  local contract replay.
- `postgres` routes actor resolution, resource-owner lookup, and safe business
  projection reads through the durable PostgreSQL repository adapter.

Repository backend selection does not change route metadata, action ids,
authorization policy, or response envelopes.

The first startup configuration gate is also platform-local. It reads:

- `STARWEAVER_PLATFORM_LISTEN_ADDR`
- `STARWEAVER_PLATFORM_ENV`
- `STARWEAVER_PLATFORM_DATABASE_URL`
- `STARWEAVER_PLATFORM_REPOSITORY_BACKEND`
- `STARWEAVER_PLATFORM_MAX_BODY_BYTES`
- `STARWEAVER_PLATFORM_REQUEST_TIMEOUT_MS`

The default profile is local and uses the `in_memory` backend for deterministic
contract tests. Production profiles (`prod` or `production`) must select the
`postgres` repository backend and provide `STARWEAVER_PLATFORM_DATABASE_URL`.
Selecting `postgres` in any environment requires a database URL so a future
binary entrypoint cannot silently build a durable backend without a durable
connection. The startup diagnostic model reports all unsafe settings together
instead of failing at the first missing value.
Platform HTTP requests are bounded by a configurable body limit and inbound
request timeout. Production validation rejects a zero or oversized body limit
and request timeouts outside the supported 100 ms to 300000 ms range.

The first binary entrypoint follows the same boundary:

- `starweaver-platform` loads `PlatformConfig`, validates the production gate,
  builds service state, and starts the foundation HTTP router.
- `starweaver-platform migrate run` applies the embedded platform migrations to
  `STARWEAVER_PLATFORM_DATABASE_URL`.
- `starweaver-platform migrate check` verifies that all embedded migration
  versions have been applied.

When the repository backend is `postgres`, startup connects to PostgreSQL, runs
the embedded migrations, and constructs `PlatformServiceState` with the durable
repository adapter before binding the HTTP listener. When the backend is
`in_memory`, startup constructs the deterministic foundation state for local
contract replay.

Generic OIDC provider configuration must be tenant-owned and contain issuer,
client id, redirect URI, requested scopes, and accepted audiences. Authorization
endpoint, token endpoint, and JWKS URI may be configured explicitly or resolved
from the issuer discovery document. Public clients use `none` token endpoint
authentication. Confidential clients reference a platform `SecretRef` and use
either `client_secret_basic` or `client_secret_post`; raw client secrets are not
stored in provider rows or returned by provider read APIs. The callback path
validates state, nonce, PKCE verifier, token expiry, issuer, audience, and
JWKS-backed ID token signature before linking or creating a local principal.
OIDC login storage is separate from gateway upstream provider OAuth or model
egress credentials.

The first platform-local OIDC contract foundation now validates the provider
shape, resolves discovery metadata, and verifies ID-token claim envelopes before
HTTP callback wiring:

- provider id and tenant id use platform id prefixes
- issuer and redirect URI must be HTTPS
- authorization endpoint, token endpoint, and JWKS URI must be HTTPS after
  explicit config and discovery metadata are resolved
- discovery issuer must match the configured issuer
- requested scopes must include `openid`
- accepted audiences must be non-empty
- `client_secret_ref` values must use `sec_` references and require a
  confidential token endpoint auth method
- provider status must be active before login use
- ID-token signing algorithms must be asymmetric and supported by the provider
- JWKS key selection uses `kid`, signing use, and algorithm constraints
- verified claims must match issuer, at least one accepted audience, expected
  nonce, non-empty subject, and a future expiration

The first durable OIDC login-attempt layer now stores OAuth state, OIDC nonce,
and PKCE verifier hashes only, records redirect URI, status, expiry, and
consumed timestamps, and loads attempts by hashing callback state before
database lookup. The HTTP callback foundation exposes
`POST /auth/v1/providers/{identity_provider_id}/callback`, requires callback
state, authorization code, raw OIDC nonce, and raw PKCE verifier, and compares
the nonce and verifier against the stored hashes before any token endpoint
exchange. It resolves provider metadata through explicit endpoints or issuer
discovery, exchanges the authorization code with the PKCE verifier, fetches
JWKS, validates the ID token, and then calls the durable completion boundary.
The first completion transaction consumes active unexpired attempts exactly
once, repairs the subject-derived local user, default organization, default
project, memberships, organization-admin role binding, external identity, and
auth session atomically, and fails closed if a provider subject is already
linked to a different local principal.

The public login foundation exposes `GET /auth/v1/providers`,
`GET /auth/v1/providers/{identity_provider_id}/login`, and
`POST /auth/v1/providers/{identity_provider_id}/start`. Provider discovery
lists the local single-user password provider only when single-user
credentials are configured, and lists active generic OIDC providers only for an
explicit tenant query such as `?tenant_id=ten_example`. Discovery responses are
safe login projections: they include provider ids, display names, issuer URLs,
login paths, start paths, requested scopes, and status, but they do not include
token endpoints, JWKS endpoints, secret refs, raw secret material, or tokens.

OIDC login and start resolve explicit or discovered provider metadata, generate
a one-time OAuth state, OIDC nonce, and PKCE S256 verifier/challenge pair,
store only the hashed attempt fields through the selected repository backend,
and return the authorization URL plus the raw client-side state values needed
for the later callback. These responses never include provider client secrets,
authorization codes, ID tokens, provider access tokens, or refresh tokens.
Non-OIDC OAuth providers, including GitHub OAuth App, require an OIDC broker or
a separate OAuth adapter before direct login support is exposed.

User session self-management exposes:

- `GET /auth/v1/session`
- `POST /auth/v1/session/active-organization`
- `POST /auth/v1/session/active-project`
- `POST /auth/v1/logout`

Session read resolves only opaque user auth sessions; API keys, service tokens,
and mTLS identities cannot use the browser session API. Login and session read
responses include CSRF metadata with the
`x-starweaver-platform-csrf-token` header name. Session mutations, including
logout, active organization switching, active project switching, and invitation
acceptance, require that header. CSRF tokens are derived from the session id and
stored token hash, so the platform never stores or returns raw session tokens
after the login response. Active organization and project updates are accepted
only when the current user has active membership in the target organization or
project. Switching to an organization clears the active project; switching to a
project sets both the organization and project from the matching membership.

Membership admin foundations expose organization and project membership reads,
organization-member create/reactivate, project-member create/reactivate, and
status mutation:

- `GET /admin/v1/organizations/{organization_id}/members`
- `POST /admin/v1/organizations/{organization_id}/members`
- `GET /admin/v1/organizations/{organization_id}/members/{organization_member_id}`
- `POST /admin/v1/organizations/{organization_id}/members/{organization_member_id}/status`
- `GET /admin/v1/projects/{project_id}/members`
- `POST /admin/v1/projects/{project_id}/members`
- `GET /admin/v1/projects/{project_id}/members/{project_member_id}`
- `POST /admin/v1/projects/{project_id}/members/{project_member_id}/status`

Organization-member create/reactivate requires `principal_id`, accepts optional
`organization_member_id`, defaults `membership_kind` to `user`, validates the
kind as `user` or `service_account`, and is idempotent by
`(organization_id, principal_id)`. Replaying the same principal returns the
existing membership; replaying a suspended or removed membership reactivates it
and advances the resource version.

Project-member create/reactivate requires an active parent organization
membership and derives the principal and membership kind from that parent
record. It is idempotent for the same `project_id` and principal, reactivates
suspended or removed project memberships, and rejects cross-organization
project assignment when existing project membership evidence places the project
under another organization. Status mutation bodies carry `expected_version`,
`status`, and an optional operator reason. Supported statuses are `active`,
`suspended`, and `removed`. Organization membership suspension or removal
cascades to matching project memberships so project-scoped access cannot
outlive organization access. Membership APIs use the same canonical
authorization path:
`platform.organization_member.read`, `platform.organization_member.write`,
`platform.project_member.read`, and `platform.project_member.write`.

Organization invitation foundations expose admin create/read/revoke routes and
public preview/accept routes:

- `GET /admin/v1/organizations/{organization_id}/invitations`
- `POST /admin/v1/organizations/{organization_id}/invitations`
- `GET /admin/v1/organizations/{organization_id}/invitations/{invitation_id}`
- `POST /admin/v1/organizations/{organization_id}/invitations/{invitation_id}/revoke`
- `GET /auth/v1/invitations/{invitation_token}/preview`
- `POST /auth/v1/invitations/{invitation_token}/accept`

Invitation create returns the raw invitation token once. Stored records and all
subsequent read, preview, revoke, and accept responses expose only safe
metadata and explicitly mark that raw token and token-hash material are not
included. Admin create/revoke use
`platform.organization_invitation.create` and
`platform.organization_invitation.manage`; admin reads use
`platform.organization_invitation.read`.

Invitation accept is a strong-auth user flow for the invited principal. It does
not require the accepting user to already hold an organization grant, because
the invitation itself is the authorization evidence for joining the
organization. Principal-target invitations create or reactivate the matching
organization membership and, when `project_id` is present, the matching project
membership. Email-target invitations can be created and safely previewed, but
the first platform foundation does not infer authorization from email alone;
email acceptance remains blocked until a verified user-profile lookup contract
exists across the selected repository backend.

The current callback foundation supports public PKCE clients and confidential
clients. `client_secret_ref` values resolve through the platform secret
repository before token exchange, and callbacks reject cross-tenant secret refs.
The durable repository stores environment-backed secret metadata, locator,
display mask, and fingerprint only; raw environment values are loaded at runtime
and fingerprint-checked before use. The in-memory backend supports write-only
raw secret values for deterministic local contract tests. Identity-provider
admin/read APIs expose:

- `POST /admin/v1/secret-refs`
- `GET /admin/v1/secret-refs`
- `GET /admin/v1/secret-refs/{secret_ref_id}`
- `POST /admin/v1/identity-providers`
- `GET /admin/v1/identity-providers`
- `GET /admin/v1/identity-providers/{identity_provider_id}`

These handlers reuse the platform-local bearer/session authentication path and
canonical authorization actions. Secret write requires
`platform.secret_ref.write`; provider configuration requires
`platform.identity_provider.write`; read paths require the matching read
actions. Provider responses mask attached `client_secret_ref` values as
`sec_***`, and neither provider nor callback responses include raw client
secrets, authorization codes, ID tokens, access tokens, or refresh tokens.

Local single-user mode is a bootstrap path, not the standard enterprise login
provider. It is disabled by default and becomes visible only when both
`STARWEAVER_PLATFORM_SINGLE_USER_USERNAME` and
`STARWEAVER_PLATFORM_SINGLE_USER_PASSWORD` are configured. Optional
`STARWEAVER_PLATFORM_SINGLE_USER_EMAIL` and
`STARWEAVER_PLATFORM_SINGLE_USER_DISPLAY_NAME` values shape the returned local
user profile. The password is read from the environment, redacted from debug
output, compared without early exit, and never persisted by the platform
schema.

The first single-user HTTP foundation exposes
`POST /auth/v1/single-user/login`. A successful login returns a one-time raw
opaque bearer session token plus session-bound CSRF metadata, stores only the
session token hash, and scopes the local user to the default tenant,
organization, and project:

- `ten_single_user`
- `org_single_user`
- `prj_single_user`
- `usr_single_user`

The foundation startup path grants the local user tenant-owner permissions so
the returned bearer token can use the same route metadata and authorization
engine as other platform sessions. Durable PostgreSQL startup can write the
session through the platform repository and now idempotently seeds or repairs
the matching tenant, organization, project, principal, user, memberships,
single-user identity provider, external identity, and tenant-owner role-binding
rows before the HTTP listener is bound.

mTLS actor resolution must consume only verified subjects from trusted service
entrypoints. A reverse proxy, service mesh, or load balancer must terminate mTLS,
verify the client certificate, strip any inbound subject headers, and set the
platform verified-subject header before the platform service resolves it to an
actor.

## Core Objects

| Object                  | Responsibility                                     |
| ----------------------- | -------------------------------------------------- |
| `Conversation`          | User-visible conversation grouping                 |
| `Session`               | Durable context and replay boundary                |
| `Run`                   | One agent execution attempt                        |
| `RunInput`              | Text, files, or structured input parts             |
| `RunEvent`              | Ordered runtime event record                       |
| `DisplayMessage`        | Client-facing projection                           |
| `Approval`              | Human decision record                              |
| `DeferredTool`          | Resumable tool call record                         |
| `EnvironmentAttachment` | Host-managed environment lease                     |
| `EvidenceArchive`       | Object storage manifest for large ordered evidence |

## Storage Split

PostgreSQL stores queryable metadata:

- tenant, project, user, and service account references
- login providers, external identities, memberships, organization invitations,
  role bindings, and action grants
- auth sessions, API keys, and service tokens by hash and status
- conversations and sessions
- runs and run status
- approvals and deferred tool records
- environment attachment leases and readiness summaries
- stream cursors and archive manifests
- idempotency keys and service outbox rows

Object storage stores large ordered evidence:

- message history snapshots and deltas
- raw runtime stream records
- display message records
- replay snapshots
- compact view snapshots
- optional trace export payloads after redaction

Redis can be used for hot state:

- live stream fanout
- short-lived idempotency coordination
- distributed locks when unavoidable
- config invalidation
- rate limiting if platform-level client limits are needed

## Candidate HTTP Resources

```text
POST /v1/conversations
GET  /v1/conversations/{conversation_id}
GET  /v1/conversations/{conversation_id}/sessions

POST /v1/runs
GET  /v1/runs/{run_id}
POST /v1/runs/{run_id}:cancel
POST /v1/runs/{run_id}:steer
GET  /v1/runs/{run_id}/events

POST /v1/approvals/{approval_id}:decide
GET  /v1/deferred-tools
POST /v1/deferred-tools/{deferred_tool_id}:resume

POST   /v1/environment-attachments
GET    /v1/environment-attachments
GET    /v1/environment-attachments/{attachment_lease_id}/health
DELETE /v1/environment-attachments/{attachment_lease_id}

GET /v1/evidence-archives/{evidence_archive_id}
GET /v1/evidence-archives/{evidence_archive_id}/debug
```

## Model Egress Contract

The platform should treat model access as a configured endpoint. In production
that endpoint is usually the gateway. In local development it may be a direct
provider endpoint or a test model service.

```mermaid
sequenceDiagram
    participant Client
    participant Platform
    participant Gateway
    participant Provider

    Client->>Platform: POST /v1/runs
    Platform->>Platform: Create run and environment binding
    Platform->>Gateway: Model request with run context
    Gateway->>Provider: Routed upstream request
    Provider-->>Gateway: Stream
    Gateway-->>Platform: Stream plus usage metadata
    Platform-->>Client: Run event stream
```

The platform may use gateway usage metadata to update run usage snapshots, but
gateway remains the source of truth for provider route, upstream credential,
route-group metrics, and model egress cost controls.
