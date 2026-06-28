# API Contracts

The repository publishes generated OpenAPI contract artifacts for the current
gateway and platform route metadata:

- [Gateway OpenAPI](openapi/gateway.openapi.json)
- [Platform OpenAPI](openapi/platform.openapi.json)

These files are generated artifacts. Do not edit them by hand.

```bash
make openapi-generate
make openapi-check
make gateway-contract-check
```

`make openapi-check` verifies that the checked-in OpenAPI files match the route
metadata compiled into the service crates. `make gateway-contract-check` also
proves the gateway route metadata, fake-provider replay cases, protocol-family
coverage, authorization action ids, provider-native denial contract, and
OpenAPI extensions stay aligned.

The current OpenAPI files intentionally use permissive request and response
schemas while the service contracts are still stabilizing. The stable contract
surface today is the path, method, operation id, authorization extensions,
resource kind, protocol family, and access boundary metadata. Typed request and
response schemas should be added incrementally once those payload contracts are
stable enough for generated clients.
