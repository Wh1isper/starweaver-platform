# UI/UX Review: Model Catalog

Status: design draft for review.

## Module Purpose

The model catalog module manages client-visible model aliases, upstream model
targets, pricing SKUs, and catalog imports. It must make protocol-family and
pricing-version constraints clear before routing policies are published.

## Entry Points

- `/models`
- `/models/aliases`
- `/models/aliases/:id`
- `/models/targets`
- `/models/targets/:id`
- `/models/pricing-skus`
- `/models/pricing-skus/:id`
- `/models/imports`

## Primary Actors

- `tenant_owner`
- `tenant_admin`
- `organization_admin`
- `project_admin`
- `gateway_operator`
- `usage_viewer` for read-only pricing and usage context when permitted

## Required Workflows

- Create a model target for a provider endpoint and protocol family.
- Create a model alias that clients can call.
- Bind or inspect the route policy for an alias.
- Create and inspect immutable pricing SKU versions.
- Validate protocol compatibility across alias, route policy, routing group,
  model target, and provider endpoint.
- Import draft catalog data without publishing runtime config automatically.

## Data Dependencies

| API                                      | Use                       |
| ---------------------------------------- | ------------------------- |
| `/api/admin/v1/model-aliases`            | list and create aliases   |
| `/api/admin/v1/model-aliases:validate`   | alias validation          |
| `/api/admin/v1/model-aliases/{id}`       | alias detail and update   |
| `/api/admin/v1/model-targets`            | list and create targets   |
| `/api/admin/v1/model-targets:validate`   | target validation         |
| `/api/admin/v1/model-targets/{id}`       | target detail and update  |
| `/api/admin/v1/pricing-skus`             | list and create pricing   |
| `/api/admin/v1/pricing-skus:validate`    | pricing validation        |
| `/api/admin/v1/pricing-skus/{id}`        | pricing detail and status |
| `/api/admin/v1/catalog-imports`          | list and create imports   |
| `/api/admin/v1/catalog-imports:validate` | import validation         |
| `/api/admin/v1/catalog-imports/{id}`     | import detail             |

## UX Decisions

- Alias pages are client-facing. Target pages are operator-facing.
- Protocol family is always visible and cannot be hidden behind advanced
  fields.
- Pricing versions are immutable once used and must be visually distinct from
  editable metadata.
- Model aliases created as drafts should clearly show whether they are callable
  yet.
- Alias detail should show route policy binding, grants, recent usage, and
  route simulation entry points.
- Target detail should show provider endpoint, credential status summary,
  capabilities, pricing, health summary, and route membership.

## Form Review

Create model target:

- provider endpoint
- upstream model id
- protocol family
- capability metadata
- pricing SKU link
- compliance and cost labels
- validation diagnostics

Create model alias:

- alias name
- organization or project namespace
- protocol family
- default route policy binding if available
- status
- validation diagnostics

Create pricing SKU:

- provider/model pattern
- pricing version
- fixed-point unit values
- currency
- effective window
- usage unit compatibility

## Empty, Loading, And Error States

| State             | UX                                                   |
| ----------------- | ---------------------------------------------------- |
| no aliases        | prompt create alias after target/provider setup      |
| no targets        | prompt provider endpoint and credential setup first  |
| protocol mismatch | show graph path causing mismatch                     |
| pricing missing   | mark cost confidence as unpriced                     |
| draft alias       | show not callable until route policy and publication |

## Redaction Review

- Model catalog pages can show provider names and endpoint ids only when
  authorized.
- Credential status is summarized without raw secret refs unless the actor has
  the required permission.
- Pricing documents never imply customer billing.

## Review Checklist

- Alias, target, route policy, routing group, endpoint, and pricing graph is
  understandable.
- Protocol-family mismatch is caught before publish.
- Pricing immutability is clear.
- Draft and active states are visually distinct.
- Catalog import cannot publish runtime config without validation.
