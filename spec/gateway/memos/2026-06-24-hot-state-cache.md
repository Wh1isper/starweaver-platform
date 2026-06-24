# Hot-State Cache Memo

Status: implementation planning memo.

Date: 2026-06-24.

This memo defines how Redis or Valkey should be used by the gateway. It is a
hot-state backend only. Durable resources, configuration, usage events, cost
ledger buckets, audit events, and notification outbox records live in
PostgreSQL.

## Decision Summary

Use Redis or Valkey for low-latency shared state that is safe to rebuild or
reconcile:

- rate and quota counters
- budget hot counters
- route stickiness
- provider health windows
- circuit breakers
- config invalidation messages
- short-lived concurrency leases

Do not store durable evidence or source-of-truth configuration only in Redis.

## Key Naming

All keys must be gateway-owned and tenant-scoped unless the data is explicitly
global.

```text
gateway:{domain}:{tenant_id}:{scope...}:{version_or_window}
```

Rules:

- include `tenant_id` for tenant data
- include `policy_id` for policy-owned counters
- include `config_version` when stale values can affect routing or policy
- hash or normalize user-provided affinity values before putting them in keys
- never include raw API key material, prompt text, completion text, upstream
  credential values, OAuth tokens, or secret reference payloads
- keep key names stable enough for dashboards and runbooks

## Key Classes

| Domain        | Example Shape                                                                          | Owner            |
| ------------- | -------------------------------------------------------------------------------------- | ---------------- |
| rate          | `gateway:rate:{tenant}:{policy_id}:{scope_kind}:{scope_id}:{window}`                   | quota policy     |
| budget        | `gateway:budget:{tenant}:{policy_id}:{scope_kind}:{scope_id}:{reset_window}`           | budget policy    |
| concurrent    | `gateway:concurrent:{tenant}:{policy_id}:{scope_kind}:{scope_id}`                      | quota policy     |
| request lease | `gateway:lease:{tenant}:{request_id}:{lease_kind}`                                     | runtime request  |
| sticky        | `gateway:sticky:{tenant}:{project_id}:{model_alias_id}:{affinity_hash}`                | route policy     |
| health        | `gateway:health:{tenant}:{provider_endpoint_id}:{window}`                              | health policy    |
| circuit       | `gateway:circuit:{tenant}:{provider_endpoint_id}:{reason}`                             | endpoint policy  |
| config        | `gateway:config:loaded:{worker_id}` and `gateway:config:invalidate:{tenant_or_global}` | config publisher |
| authn         | `gateway:authn_fail:{tenant_or_global}:{credential_prefix_or_ip}:{window}`             | auth policy      |

## TTL Rules

| Key Class     | TTL Rule                                                |
| ------------- | ------------------------------------------------------- |
| rate          | policy window plus small grace                          |
| budget        | reset window plus reconciliation grace                  |
| concurrent    | request deadline plus cleanup lag                       |
| request lease | request deadline plus cleanup lag                       |
| sticky        | route sticky policy TTL                                 |
| health        | health window plus small grace                          |
| circuit       | breaker cool-down TTL                                   |
| config        | invalidation messages have no durable TTL requirement   |
| authn         | short failure window defined by abuse-prevention policy |

Keys without TTL require an explicit exception in the owning spec.

## Atomicity

Use a single Redis command or Lua script when multiple operations must be
observed as one policy decision.

Required atomic operations:

- check and increment request/token counters
- reserve budget hot counter if projected cost stays within allowance
- acquire and release concurrency leases idempotently
- update circuit breaker state with compare-and-set semantics
- write sticky mapping only when the target remains eligible for the active
  config version

Script outputs should return structured decision data:

```json
{
  "allowed": true,
  "policy_id": "pol_...",
  "counter_value": 42,
  "limit": 100,
  "reset_at": "2026-06-24T00:01:00Z",
  "mode": "normal"
}
```

Scripts must not log or return secret material.

## Failure Modes

| Capability       | Cache Unavailable Default                                     |
| ---------------- | ------------------------------------------------------------- |
| route stickiness | ignore sticky mapping and route from current config           |
| provider health  | treat health as unknown unless config marks endpoint disabled |
| circuit breaker  | use config state and fresh attempts; do not infer durability  |
| soft budget      | allow or notify according to budget policy                    |
| hard budget      | fail closed unless policy declares bounded fail-limited mode  |
| rate limit       | policy-defined `fail_open`, `fail_limited`, or `fail_closed`  |
| concurrency      | policy-defined; production defaults should be conservative    |
| config reload    | rely on PostgreSQL version polling                            |

Any fail-limited mode must define:

- maximum requests
- maximum estimated cost or tokens
- time window
- affected scopes
- audit event shape
- operator alert

## Reconciliation

Redis values are reconciled from PostgreSQL evidence:

1. Usage events append to durable storage.
2. Ledger workers fold usage into durable buckets.
3. Reconciliation compares hot budget counters with durable bucket totals.
4. Differences are repaired when safe.
5. Hard-capped scopes enter conservative mode when hot state is lower than
   durable usage or cannot be trusted.
6. Repairs that affect enforcement write audit evidence.

Rate counters are short-lived and may not need durable repair, but usage and
budget counters need reconciliation because they affect spend controls.

## Deployment Topology

V1 should support:

- local single-node Redis or Valkey through Docker Compose
- production managed Redis or Valkey with TLS
- Sentinel or managed failover when operator infrastructure provides it

The gateway should not require Redis Cluster in v1. If Redis Cluster is used,
scripts and multi-key operations must keep keys in a compatible hash slot or be
disabled for policies that require cross-key atomicity.

## Observability

Minimum metrics:

- cache command latency
- script latency by script id
- cache error count by operation
- cache unavailable duration
- budget conservative mode count
- fail-limited allowance consumed
- config invalidation lag
- worker loaded config version
- reconciliation repair count

Logs must use key class and scope metadata, not full raw key strings when keys
could contain hashed affinity or customer-controlled identifiers.

## Tests

Required tests:

- key construction rejects unsafe input
- every key class has TTL or an explicit exception
- atomic scripts enforce limits under concurrent requests
- hard budget cache loss fails according to policy
- missed PubSub invalidation converges through polling
- reconciliation repairs stale hot counters
- sticky routing degrades safely when cache is unavailable
- Redis restart during a streaming request does not lose usage evidence

## Acceptance Gates

- Redis or Valkey is never the source of truth for durable gateway evidence.
- Each hot-state key has owner, TTL, scope, failure mode, and recovery path.
- Atomic policies are backed by scripts or single-command guarantees.
- Production hard budget behavior is conservative under cache loss.
- Local validation can run Postgres and Redis through compose or
  `testcontainers`.
