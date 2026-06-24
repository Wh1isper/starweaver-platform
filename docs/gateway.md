# LLM Gateway

The LLM gateway is the model egress plane for Starweaver service deployments. It
provides enterprise model routing, upstream credential management, policy
enforcement, budget tracking, audit, and observability for outbound model
traffic.

## Core Responsibilities

- Authenticate inbound client credentials.
- Authorize model aliases and scopes.
- Resolve routing groups, policies, provider endpoints, and upstream
  credentials.
- Enforce rate limits and budgets.
- Forward requests within compatible protocol families.
- Record usage, cost estimates, routing decisions, and audit evidence.

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
- Bedrock Native.
