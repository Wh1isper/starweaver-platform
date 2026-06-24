# Agent Platform

The agent platform service is the hosted agent control plane. It owns HTTP
resources for conversations, sessions, runs, approvals, deferred tools,
environment attachments, stream replay, and durable execution evidence.

## Core Responsibilities

- Authenticate and authorize tenant, project, user, and service account access.
- Create and manage conversations, sessions, and runs.
- Persist queryable run metadata.
- Archive large ordered evidence in object storage.
- Expose replayable run event streams.
- Coordinate environment attachments through host-facing contracts.
- Use the LLM gateway as a model egress option without importing gateway
  internals.

## Storage Split

PostgreSQL stores metadata needed for listing, authorization, recovery, and
cursor lookup. Object storage stores ordered evidence such as raw events,
display messages, message history snapshots, replay snapshots, and compact view
snapshots.

Redis can be introduced for live stream fanout, config invalidation,
rate-limiting, and short-lived coordination once the service loop exists.
