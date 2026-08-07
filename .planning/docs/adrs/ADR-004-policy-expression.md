# ADR-004: Policy expression and compilation model

## Status

Proposed

## Context

Administrators define data classifications and rules. The server validates and compiles rules; the agent evaluates the compiled bundle locally. The model must be:
- Deterministic for the same policy version and input.
- Safe to evaluate on untrusted file metadata and content.
- Bounded in time and memory.
- Testable independently of Windows APIs.

Candidates considered:
- **JSON/YAML rule DSL** — human-writable, easy to version, but requires careful validation.
- **Embedded scripting language (Lua, Rhai)** — flexible, but risks non-termination and excessive resource use.
- **Compiled decision table** — fast and deterministic, but less expressive.

## Decision

Use a **declarative JSON rule DSL** compiled into an internal decision structure.

Rules support conditions on file properties (name, extension, MIME type, path, size), content detectors (regex, dictionary, hash, structured identifier), operation context, and destination context. Actions are limited to `allow`, `block`, `allow_and_audit`, and `warn` in the MVP. The server rejects policies that use `require_justification` until the workflow is implemented.

## Consequences

- **Positive:** Deterministic, bounded, easy to unit test, versionable.
- **Positive:** Domain crate `dlp-policy` can be shared by server and agent.
- **Negative:** Less flexible than a scripting language; complex conditions may require multiple rules.
- **Risk:** Regex-based detectors must use bounded engines to avoid ReDoS and excessive memory.

## Compilation and Validation

- Server validates rule syntax, condition references, priority, conflict detection, and assignment targets.
- Compiled bundle contains ordered rules, default action, schema version, and metadata.
- Agent deserializes and evaluates the bundle without executing arbitrary code.
- Every decision records the matched rule, action, and reason code.

## References

- PROJECT.md policy engine requirements
- THREAT-MODEL.md denial-of-service and tampering mitigations
