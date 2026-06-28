# Starweaver Platform

Starweaver Platform is the enterprise service workspace for the hosted agent
platform and LLM gateway.

This repository is intentionally separate from the Starweaver SDK/runtime
repository. The SDK/runtime repository owns core agent execution, model
provider abstractions, tools, envd integration, CLI, and local host protocols.
This repository owns service-side infrastructure such as tenancy, credentials,
policy, audit, usage, deployment, and hosted APIs.

## Documentation Map

- [Install](install.md) - local setup and repository commands.
- [Testing](testing.md) - local and CI validation.
- [API Contracts](api-contracts.md) - generated OpenAPI artifacts and contract
  gates.
- [Service Boundary](architecture.md) - repository and service ownership.
- [Agent Platform](agent-platform.md) - hosted agent control plane.
- [LLM Gateway](gateway.md) - enterprise model egress plane.
- [Operations](operations.md) - docs deployment and release direction.

## Design Specs

Architecture decisions live in `spec/`. The docs site summarizes the stable
operator-facing shape and links back to the repository for detailed specs.
