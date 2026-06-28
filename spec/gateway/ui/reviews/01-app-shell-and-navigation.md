# UI/UX Review: App Shell And Navigation

Status: design draft for review.

## Module Purpose

The app shell provides the persistent enterprise workspace for all gateway
console modules. It owns scope, navigation, session context, command/search,
time range, and responsive layout.

## Entry Points

- `/`
- `/overview`
- `/realtime`
- any deep-linked resource or dashboard route
- local single-user login redirects into the shell after session resolution
- generic OIDC login callback redirects into the shell after session resolution

## Primary Actors

- all authenticated user roles
- unauthenticated users during login and invitation acceptance

## Required Surfaces

| Surface         | Requirements                                                                 |
| --------------- | ---------------------------------------------------------------------------- |
| Sidebar         | Product sections, role-aware visibility, collapsed mode, keyboard navigation |
| Top bar         | tenant, organization, project, time range, command/search, current user      |
| Scope switcher  | active organization and project, default organization repair state           |
| Breadcrumbs     | scope-aware hierarchy for details and nested resources                       |
| Command palette | navigate, find resources, jump to recent evidence, trigger safe actions      |
| Session menu    | profile, active sessions, logout, default organization                       |
| Error boundary  | route-level recovery, request id, safe support details                       |
| Access denied   | show missing action/resource when safe                                       |

## Information Architecture Review

The shell should group navigation by work mode:

- Operate: Overview, Realtime Ops, Usage, Observability
- Configure: Models, Routing, Providers, Policy
- Govern: Access, Evidence, Operations, Settings

Navigation must not mirror backend resource families one-for-one when that
would hide user workflows. For example, `provider grants` belongs in Policy,
while provider endpoint health belongs in Realtime Ops and Providers.

## UX Decisions

- The first screen after login is the highest authorized Overview scope.
- Tenant-level actors default to tenant overview.
- Organization actors default to organization overview.
- Project actors default to project overview.
- Scope switching is global but pages may constrain invalid scope combinations.
- Time range is global for dashboard pages and ignored by pure configuration
  pages.
- The command palette must never expose actions the actor cannot perform.
- Breadcrumbs should include resource names and ids where ambiguity matters.

## Empty, Loading, And Error States

| State                  | UX                                                                           |
| ---------------------- | ---------------------------------------------------------------------------- |
| no active organization | show repair/setup flow from session API                                      |
| no project selected    | allow organization-level pages and prompt project selection only when needed |
| session expired        | show re-auth prompt without losing current URL                               |
| API unavailable        | show gateway request id and retry, not a blank shell                         |
| access denied          | show safe action/resource context and navigation back                        |
| config stale           | show a shell-level warning only when it affects current page                 |

## Accessibility Review

- Sidebar, command palette, dropdowns, and dialogs use accessible primitives.
- Keyboard users can reach scope switcher, search, navigation, content header,
  and primary page actions in order.
- Focus returns to the invoking control after dialog close.
- Collapsed sidebar labels are available through accessible names and tooltips.

## Implementation Notes

- Use TanStack Router route contexts for session and authorization state.
- Persist shareable filters in URL search params.
- Keep non-shareable UI state local.
- Use TanStack Query for `/api/auth/v1/session`.
- Use MSW session fixtures for all canonical roles.
- Use the backend CSRF header `x-gateway-csrf-token` for browser session
  mutations once `/api/auth/v1` is mounted.

## Review Checklist

- Role-aware navigation matches gateway actions.
- Deep links work after browser refresh.
- SPA fallback does not intercept `/api/*`.
- Browser code does not call root-level `/auth/v1` or `/admin/v1` paths.
- Scope switch changes invalidate affected queries.
- The shell works in the production Docker image.
- No page requires marketing-style onboarding text to be usable.
