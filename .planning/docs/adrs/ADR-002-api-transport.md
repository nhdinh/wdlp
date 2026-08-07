# ADR-002: Server API transport and protocol format

## Status

Proposed

## Context

The management server exposes APIs to administrators and enrolled agents. The protocol must:
- Be versioned and stable for agent-server communication.
- Support efficient signed bundle downloads.
- Support batched, idempotent event uploads.
- Be easy to generate documentation and client code for.

Candidates considered:
- **HTTP/1.1 + REST + JSON** — simple, universally supported, easy to debug.
- **HTTP/2 + gRPC + Protobuf** — efficient streaming, strong schema, generated clients.
- **HTTP/2 + REST + JSON** — middle ground; HTTP/2 for multiplexing without gRPC complexity.

## Decision

Use **HTTP/1.1 and HTTP/2 with REST-style JSON endpoints** for both admin and agent APIs.

Server-sent events or simple long-polling can be added later for configuration push; the initial sync model is agent-polling with heartbeat.

## Consequences

- **Positive:** Simple to implement, test, and debug with curl/HTTP tools.
- **Positive:** JSON aligns with the administrative web UI and CLI.
- **Positive:** TLS termination is well supported by reverse proxies and containers.
- **Negative:** Less bandwidth-efficient than gRPC+Protobuf for very large bundles; acceptable because bundles are signed policy/config, not bulk file data.
- **Negative:** Schema discipline relies on serde + validation rather than Protobuf; requires careful versioned DTO design.

## Versioning

- API version in URL path: `/api/v1/...`.
- Bundle schema version embedded in signed payloads.
- Agents reject bundles with unsupported schema versions after signature verification.

## References

- PROJECT.md scope and API categories
- dlp-protocol crate responsibility in workspace structure
