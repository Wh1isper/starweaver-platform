# UI/UX Review: Access And Identity

Status: design draft for review.

## Module Purpose

Access and identity pages manage organizations, projects, users, memberships,
invitations, identity providers, sessions, API keys, service accounts, and
action grants. The UI must make scope and permission narrowing explicit.

## Entry Points

- `/access`
- `/access/organizations`
- `/access/organizations/:id`
- `/access/projects`
- `/access/projects/:id`
- `/access/users`
- `/access/users/:id`
- `/access/invitations`
- `/access/api-keys`
- `/access/api-keys/:id`
- `/access/service-accounts`
- `/access/service-accounts/:id`
- `/settings/identity-providers`
- `/settings/sessions`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `security_admin`
- `organization_admin`
- `project_admin`
- `auditor` for read-only identity evidence where permitted

## Required Workflows

- Invite a user into an organization.
- Add or change project membership.
- Suspend or remove organization/project member.
- Use local single-user login when the deployment enables it.
- Configure generic OIDC identity provider.
- Inspect external identities and sessions.
- Revoke a session.
- Plan API key lifecycle UX, but keep create, rotate, disable, and one-time
  reveal hidden until admin API key endpoints exist.
- Create, update, disable, and inspect service accounts.
- Show action-grant or role-binding views only after the corresponding gateway
  admin endpoints exist.

## Data Dependencies

| API                                                     | Use                                        |
| ------------------------------------------------------- | ------------------------------------------ |
| `/api/auth/v1/session`                                  | current session and memberships            |
| `/api/auth/v1/session/active-organization`              | switch active organization                 |
| `/api/auth/v1/session/active-project`                   | switch active project                      |
| `/api/auth/v1/single-user/login`                        | local single-user login when configured    |
| `/api/auth/v1/providers`                                | public login provider discovery            |
| `/api/auth/v1/providers/{id}`                           | safe login provider detail                 |
| `/api/auth/v1/providers/{id}/login`                     | start generic OIDC login                   |
| `/api/auth/v1/providers/{id}/callback`                  | complete generic OIDC login callback       |
| `/api/auth/v1/invitations/{token}/preview`              | safe invitation preview                    |
| `/api/auth/v1/invitations/{token}/accept`               | accept invitation with CSRF                |
| `/api/admin/v1/organizations`                           | list organizations                         |
| `/api/admin/v1/organizations/{id}`                      | organization detail and update             |
| `/api/admin/v1/organizations/{id}/members`              | organization members                       |
| `/api/admin/v1/organizations/{id}/invitations`          | invitations                                |
| `/api/admin/v1/projects`                                | project list                               |
| `/api/admin/v1/projects/{id}`                           | project detail and update                  |
| `/api/admin/v1/projects/{id}/members`                   | project members                            |
| `/api/admin/v1/users/*`                                 | user management                            |
| `/api/admin/v1/users/{id}/sessions`                     | user session list                          |
| `/api/admin/v1/users/{id}/sessions/{session_id}/revoke` | strong-auth session revoke                 |
| `/api/admin/v1/users/{id}/external-identities/*`        | external identity list, detail, and unlink |
| `/api/admin/v1/identity-providers/*`                    | login provider config                      |
| `/api/admin/v1/service-accounts`                        | service account list and create            |
| future API key endpoints                                | API key lifecycle                          |

## UX Decisions

- Organization is the product-facing tenant boundary.
- Tenant is visible to tenant operators but should not dominate daily project
  workflows.
- Project membership changes show usage visibility impact.
- API key permissions are always described as narrowing the owner principal.
- Service accounts are principals, not anonymous credentials.
- Raw API key values are shown only once immediately after creation.
- Session revocation and user disable are security actions with reason and
  audit impact.
- Browser session mutations require `x-gateway-csrf-token`.
- Direct GitHub OAuth App login is not a v1 gateway UI path; GitHub Enterprise
  should be represented through a generic OIDC broker until a separate adapter
  is reviewed.

## One-Time API Key Reveal

This is a phased workflow until API key admin endpoints exist. The create-key
success screen must eventually:

- show the raw key once
- provide copy control
- warn that the key cannot be read again
- show key prefix and owner
- show scope and narrowing policy
- show created audit event id
- provide done and rotate/disable follow-up actions

After leaving the screen, only the masked prefix and metadata remain.

## Empty, Loading, And Error States

| State                       | UX                                                                        |
| --------------------------- | ------------------------------------------------------------------------- |
| no projects                 | organization admin sees create project; other users see no project access |
| invite expired              | show safe preview and request new invite path                             |
| default org missing         | show repair action for authorized admins or support text                  |
| key disabled                | show disabled state and history                                           |
| permission narrowed to none | warning before saving action grant                                        |

## Redaction Review

- Email display follows gateway policy. Hash-only fields are not expanded by UI.
- External identity subjects are shown only when authorized.
- Session IP/user-agent fields use safe metadata from API.
- API key hash values are never shown.

## Review Checklist

- Scope hierarchy is clear: tenant -> organization -> project.
- API keys cannot appear to grant broader access than their owner.
- One-time key reveal is enforced by UI state.
- Invitation acceptance and preview are safe.
- User disable and session revoke flows require appropriate confirmation.
- API key pages remain read-only or hidden until lifecycle endpoints are added.
