# UI/UX Review: Routing And Simulation

Status: design draft for review.

## Module Purpose

Routing pages let operators manage routing groups, route policies, target
membership, failover, sticky routing, drain, canary, and simulation. The module
must explain both selection and exclusion.

## Entry Points

- `/routing`
- `/routing/groups`
- `/routing/groups/:id`
- `/routing/groups/:id/targets`
- `/routing/policies`
- `/routing/policies/:id`
- `/routing/simulate`
- `/routing/decisions`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `gateway_operator`
- `organization_admin` where scoped resources permit
- `auditor` for read-only route evidence

## Required Workflows

- Create a routing group for one protocol family.
- Add and weight model targets inside a group.
- Create a route policy that binds ordered groups to a model alias.
- Simulate a route for organization, project, credential, model alias,
  protocol family, request metadata, and budget mode.
- Inspect why candidates were selected, denied, filtered, or failed over.
- Drain a group or endpoint with reason and expiry when required.

## Data Dependencies

| API                                                  | Use                               |
| ---------------------------------------------------- | --------------------------------- |
| `/api/admin/v1/routing-groups`                       | list and create routing groups    |
| `/api/admin/v1/routing-groups:validate`              | group validation                  |
| `/api/admin/v1/routing-groups/{id}`                  | group detail and status           |
| `/api/admin/v1/routing-groups/{id}/targets`          | membership list and create        |
| `/api/admin/v1/routing-groups/{id}/targets:validate` | membership validation             |
| `/api/admin/v1/route-policies`                       | list and create policies          |
| `/api/admin/v1/route-policies:validate`              | policy validation                 |
| `/api/admin/v1/route-policies/{id}`                  | policy detail and update          |
| `/api/admin/v1/route-simulations`                    | route simulation                  |
| future `/api/admin/v1/models/aliases/{id}/routes`    | dedicated alias route diagnostics |

## UX Decisions

- Routing group is the primary traffic control unit.
- Route policy pages show ordered group plan, not just a flat target list.
- Simulation output is a first-class page and a side panel on policy pages.
- Filtering reasons must be grouped by policy, grant, health, budget, quota,
  protocol, status, and compliance.
- Privileged actors can see exact provider/resource labels; other actors see
  redacted labels and counts.
- Streaming failover boundaries must be visible in policy configuration.

## Simulation Result Shape

Simulation UI should present:

- input context and effective scope
- resolved model alias
- provider grant closure
- route policy and group expansion
- eligible candidates
- denied candidates
- filtered candidates by reason
- selected target and fallback candidates
- budget and quota posture
- sticky mapping outcome
- failover plan and stream-lock behavior
- warnings and publication impact

## Visual Review

- Prefer a structured stepper or expandable pipeline over a dense graph for
  simulation details.
- Use a compact graph only for alias -> policy -> group -> target -> endpoint.
- Keep weights, priority, traffic percent, and canary percent editable through
  tables with validation.
- Drain and disable actions must be visually distinct.

## Empty, Loading, And Error States

| State                       | UX                                                      |
| --------------------------- | ------------------------------------------------------- |
| no routing groups           | prompt create group after target setup                  |
| group has no targets        | show non-callable state and add-target action           |
| policy has no primary group | blocking diagnostic                                     |
| all candidates filtered     | show reason counts and first repair action              |
| simulation unavailable      | show gateway error, request id, and validation fallback |

## Review Checklist

- Operators can explain selected and excluded targets.
- Protocol-family mismatches are visible.
- Drain does not look like delete.
- Sticky and failover policies are understandable.
- Route simulation can be reached from alias, policy, and routing pages.
- Streaming failover constraints are visible before publish.
