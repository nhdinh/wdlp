# Phase 1 Evidence Contract

Phase 1 accepts evidence only through `phase1-evidence/v1`. Each attempt has a unique immutable ID, a named machine/role, UTC timestamp, build/procedure/environment provenance, expected and actual stable result, raw-artifact hash, retention state, and an allowlisted redaction result.

Store raw output under ignored controlled storage such as `target/phase1-evidence/`; commit only sanitized manifests and checklist records. A missing, inaccessible, or hash-mismatched raw artifact invalidates a passing result unless the manifest is explicitly self-contained. Never place credentials, private keys, tokens, protected plaintext, sensitive command arguments, raw hardware serials, or unrelated volatile state in the repository.

The four verification tiers are ordered: `portable_automation`, `focused_hyperv`, `signed_visual_checklist`, and `phase_exit_review`. Lower tiers never satisfy a higher boundary. `hungdinh-lt` is limited to the portable/developer role; endpoint, service, DPAPI, WinFsp, user-session, restart, and visual evidence must be gathered on the named lab VM.

Failed attempts remain immutable. A rerun publishes a new ID and includes `prior_attempt_id`, `remediation_commit`, and `supersedes_evidence_id`; only the matrix pointer changes. Procedure/configuration/binary/baseline digests make affected rows stale without invalidating unrelated evidence.

Visual and independent-review records require an authenticated domain identity, UTC, target machine, build, expected/actual result, deviations, matrix digest, and artifact-integrity result. Failure or security evidence remains retained or held through the milestone audit and is securely deleted only after the documented retention deadline when no hold applies.
