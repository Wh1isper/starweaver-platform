# Gateway Memos

Status: working notes for implementation planning.

This directory holds implementation-selection memos for the gateway.
These documents are not protocol specs. They record concrete engineering
choices and rejected alternatives before the gateway service is implemented.

## Memo Index

- `2026-06-24-framework-selection.md` - framework and library choices for the
  first gateway implementation.
- `2026-06-24-hot-state-cache.md` - Redis or Valkey key, TTL, atomicity,
  failure-mode, and reconciliation decisions.

## Rules

- Keep memos concrete: name the chosen crate, service, or pattern.
- Separate v1 required dependencies from optional later integrations.
- Promote decisions from memos into `spec/gateway/*.md` only when they become
  stable product or protocol requirements.
