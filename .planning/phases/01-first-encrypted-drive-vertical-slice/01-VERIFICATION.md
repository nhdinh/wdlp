---
phase: 01-first-encrypted-drive-vertical-slice
verified: 2026-08-25T15:30:00Z
status: gaps_found
score: 7/10 must-haves verified
behavior_unverified: 0
overrides_applied: 0
re_verification:
  previous_status: gaps_found
  previous_score: 7/11
  gaps_closed:
    - "Affirmed payload and predecessor digest are rechecked under the publication lock before signing."
    - "Current signed-off validation enforces key usage, EKU, online revocation, and process-scoped CustomRootTrust."
    - "Lexical rooted/traversal/prefix/mixed-separator references are rejected."
    - "Forgery, two-writer, crash-before-replace, and FinalGate regressions now execute behaviorally."
  gaps_remaining:
    - "Signing does not bind observed executing user and machine to the authorized policy reviewer."
    - "Superseded CMS signatures are not authenticated during signed-off verification."
    - "Lexical containment can be bypassed through a Windows reparse point."
  regressions: []
gaps:
  - truth: "Only approved LAB\\dlp-reviewer on D-22 (LAB-DC02) can publish a reviewer attestation"
    status: failed
    reason: "Publisher copies identity and machine from policy without comparing them with the executing Windows context."
    artifacts:
      - path: "scripts/add-security-closure-review.ps1"
        issue: "Lines 16 and 22 display the observed machine but sign policy-asserted identity/machine values."
    missing:
      - "Require observed Windows identity and COMPUTERNAME to match the single policy reviewer before prompt or mutation."
      - "Populate attestation from observed values and add wrong-user/wrong-machine non-mutation regressions."
  - truth: "The complete append-only attestation history remains cryptographically authentic and auditable"
    status: failed
    reason: "Only the latest CMS signature is verified; historical signature bytes are excluded from predecessor digests and may be corrupted undetected."
    artifacts:
      - path: "scripts/verify-phase1-security.ps1"
        issue: "Lines 43-44 check linkage for all entries but call Test-SignedAttestation only for the latest."
    missing:
      - "Verify every historical CMS signature under its trust contract, or use a signed archival envelope committing to historical signature bytes."
      - "Add a superseded-signature byte-flip regression requiring signature_invalid."
  - truth: "All security artifact references resolve to real filesystem targets contained within the repository"
    status: failed
    reason: "GetFullPath plus StartsWith proves lexical containment only; a repository junction or symlink can redirect reads externally."
    artifacts:
      - path: "scripts/verify-phase1-security.ps1"
        issue: "Lines 15-19 do not reject or resolve reparse points before hashing."
    missing:
      - "Reject reparse points or resolve the filesystem target and prove canonical repository containment."
      - "Add junction and symlink escape regressions with a stable diagnostic."
---

# Phase 01: First Encrypted-Drive Vertical Slice Verification Report

**Phase Goal:** An authorized Windows user can enroll, receive signed configuration, mount a private protected WinFsp drive, write/read files through encrypted backing storage, and recover safely across restart while Phase 1 evidence remains fail-closed and trustworthy.
**Status:** gaps_found
**Re-verification:** Yes — after Plan 01-34 hardened closure

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| SC-01 | Safe Rust workspace with Windows integration isolated | VERIFIED | Workspace/crates, unsafe boundaries, portable tests, and FinalGate evidence remain present. |
| SC-02 | PostgreSQL-backed enrollment/readiness works on the assigned topology | VERIFIED | Server/repository wiring and real-PostgreSQL evidence remain intact; FinalGate reports 30/30 requirements. |
| SC-03 | LAB-CLIENT01 enrolls and activates only valid signed configuration | VERIFIED | Enrollment, mTLS, DPAPI credential, cache/activation implementation and evidence remain present. |
| SC-04 | Eligible users receive a usable SID-bound WinFsp drive | VERIFIED | Service/session-host to WinFsp wiring and mounted-drive matrix remain intact. |
| SC-05 | Writes create authenticated encrypted backing data without readable plaintext | VERIFIED | AES-GCM storage, metadata protection, atomic commit tests/evidence remain present. |
| SC-06 | Reads authenticate data and corruption releases no plaintext | VERIFIED | Integrity paths and behavioral tests/evidence remain present. |
| SC-07 | Committed files survive restart and interrupted replacement atomically | VERIFIED | Recovery code and restart/reboot/abrupt-loss/application evidence remain present. |
| SEC-05 | Ceremony is bound to observed `LAB\\dlp-reviewer` on `LAB-DC02` | FAILED | Publisher asserts identity/machine from policy without enforcing executing context. |
| SEC-06 | Every append-only attestation remains cryptographically authenticated | FAILED | Only latest CMS is checked. |
| SEC-07 | Artifact hashing cannot escape through Windows filesystem indirection | FAILED | Lexical containment follows junctions/symlinks externally. |

**Score:** 7/10 truths verified (0 behavior-unverified).

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| Phase 1 workspace/crates | Functional vertical slice | VERIFIED | Substantive and wired; no functional regression observed in closure changes. |
| `evidence/phase1/requirement-matrix.yaml` | Requirement-indexed evidence | VERIFIED | FinalGate: 34/34 checks, 30/30 requirements, 7/7 criteria, 50/50 decisions, 9/9 privilege manifests. |
| `evidence/phase1/security-closure.yaml` | Externally authenticated closure | PARTIAL | Current 19 attestations pass implemented verifier; manifest `4b30d328d5967f8f2346be1d61811b8ae56b26404dc8bef0150e61ba1619c591`, but history is not fully authenticated. |
| `scripts/add-security-closure-review.ps1` | D-22-bound consent/publication | FAILED | Consent continuity and durability exist, but execution identity/station is not enforced. |
| `scripts/verify-phase1-security.ps1` | Fail-closed signed-off validation | FAILED | Current trust is hardened, but historical CMS and reparse containment are not verified. |
| `scripts/evidence/Phase1.Security.Tests.ps1` | Adversarial regressions | PARTIAL | Focused suite passes but lacks wrong-station, historical-signature-tamper, and reparse escape cases. |

### Key Links and Data Flow

| Link/data | Status | Details |
| --- | --- | --- |
| Service/session host → WinFsp/storage | WIRED | Functional slice remains connected and evidenced. |
| Confirmation preview → published CMS | WIRED | Approved payload/predecessor comparison now occurs under mutex. |
| Policy → current signer trust | WIRED | Thumbprint, identity, usage, EKU, online revocation, custom root; policy `edfa1018ee5c9fbb5073af0a16b71bf82e83f144a48568164b8a691fdff960fd`. |
| Executing Windows context → claimed reviewer context | NOT WIRED | Publication signs policy values, not enforced observed values. |
| Historical chain → CMS authenticity | NOT WIRED | Digest excludes CMS bytes; only latest CMS is checked. |
| Artifact path → repository boundary | PARTIAL | Lexical paths bounded; reparse targets are not. |

### Behavioral Spot-Checks

| Behavior | Result | Status |
| --- | --- | --- |
| `scripts/evidence/Phase1.Security.Tests.ps1` | Completed successfully during re-verification | PASS WITH COVERAGE GAPS |
| Signed-off verifier | User-provided run: valid, zero diagnostics, manifest `4b30...c591`, policy `edfa...60fd` | PASS FOR CURRENT ATTESTATIONS |
| Canonical FinalGate | 34/34 checks, 30/30 requirements | PASS, TRUST GAPS REMAIN |
| Wrong-station signing rejection | No enforcement/test | FAIL |
| Superseded CMS corruption rejection | No enforcement/test | FAIL |
| Junction/symlink escape rejection | No enforcement/test | FAIL |

### Probe Execution

No `probe-*.sh` is declared. Phase-specific PowerShell checks were used.

### Requirements Coverage

| Requirement | Status | Evidence |
| --- | --- | --- |
| WRK-01, WRK-02, WRK-03, WRK-04 | SATISFIED | Workspace, shared types/protocols, unsafe isolation, tests/evidence present. |
| SRV-01, SRV-03, SRV-11, SRV-12 | SATISFIED | APIs, enrollment, PostgreSQL migrations, health/readiness, lab evidence present. |
| CRY-01, CRY-02 | SATISFIED | Authenticated storage and strict signed-config activation implemented/tested. |
| CRY-04 | BLOCKED | Secret handling exists, but the phase-wide trustworthy evidence contract is defeated by CR-05 through CR-07. |
| AGT-01, AGT-02, AGT-03, AGT-04, AGT-05, AGT-06, AGT-07 | SATISFIED | Service, protected credentials, TLS, configuration lifecycle, LKG, rejection, health evidenced. |
| DRV-01, DRV-02, DRV-03, DRV-04, DRV-06, DRV-07, DRV-09 | SATISFIED | Per-user mapping, encryption, crash consistency, corruption denial, restart recovery evidenced. |
| TST-01, TST-02, TST-03, TST-05, TST-08 | SATISFIED WITH WARNING | Required functional coverage exists; security regressions omit the three blocker attacks. |

All 30 requested IDs are claimed by Phase 1 plan frontmatter and cross-referenced to `REQUIREMENTS.md`; none is orphaned.

### Anti-Patterns and Test Quality

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `scripts/add-security-closure-review.ps1` | 16, 22 | Policy-asserted execution identity/station | BLOCKER | Key access can yield a false D-22 attestation. |
| `scripts/verify-phase1-security.ps1` | 43-44 | Only latest CMS verified | BLOCKER | Superseded signature corruption is undetected. |
| `scripts/verify-phase1-security.ps1` | 15-19, 42 | Lexical-only containment | BLOCKER | Reparse points redirect hashing externally. |
| `scripts/verify-phase1-security.ps1` | 21-22 | Caller environment removed, not restored | WARNING | Nested verification can destroy caller state (WR-02). |

No disabled requirement-linked tests or unreferenced `TBD`/`FIXME`/`XXX` markers were observed in the reviewed security files.

### Decision Coverage

FinalGate reports 50/50 decisions. D-22 is correctly documented as `LAB-DC02`; CR-05 is a runtime enforcement failure of that decision.

### Human Verification Required

None. These gaps are deterministic source/test failures; UAT cannot establish the missing invariants.

### Deferred Items

None. Trustworthy Phase 1 evidence is explicit in the phase goal and cannot be deferred.

### Gaps Summary

The functional vertical slice and current signed evidence pass implemented gates, and Plan 01-34 closes the four prior gaps. The goal remains unachieved because the ceremony is not bound to observed D-22 identity/station, historical CMS signatures are unauthenticated, and artifact containment is bypassable via Windows reparse points. WR-02 is non-blocking.

**Next action:** create and execute focused Phase 01 gap closure for CR-05, CR-06, and CR-07 (preferably WR-02 too), then rerun `$gsd-execute-phase 01 --gaps-only` and Phase 01 verification. Do not advance the milestone.

---

_Verified: 2026-08-25T15:30:00Z_  
_Verifier: Codex (gsd-verifier)_

## Derived Operational Verification Interval (Non-Authoritative)

**Interval:** 2026-08-26T08:53:00Z through 2026-08-26T09:00:00Z  
**Classification:** `derived_non_authoritative`  
**Authoritative signed generation:** `000001-14cf058854cf0679`  
**Generation commitment:** CMS-signed `generation.json` under `evidence/phase1/independent-reviews/000001-14cf058854cf0679/`  
**Signer:** `LAB\\d48-reviewer` on `LAB-CLIENT01`  
**Signer certificate:** `DB1742CE5481D4F3F98BFBD38D8637EFA0203825`  
**D-48 policy:** `phase1-d48-independent-review-2026-08-26`  
**D-48 trust root:** `9BD5C327444EBF5EBAE3139F77A48E044EACBD0A` / SHA-256 `4AD4555D26B23C0E3D0143EF7759114BC73F3B5C40272C4536FC6C8986485610`

### Commands and Results

| Command | Result |
| --- | --- |
| `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Evidence.Tests.ps1` | PASS (exit 0) |
| `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/evidence/Phase1.Security.Tests.ps1 -Focus Publication` | PASS (exit 0) |
| `scripts/verify-phase1.ps1` with archival and D-48 public trust/policy paths | BLOCKED: authenticated security subgate reports `T-01-21-04 file digest mismatch scripts/add-independent-review.ps1`; the independent-review module also reports the pre-existing archival policy `subject` compatibility failure under Windows PowerShell |
| Isolated copied-fixture mutations of `security_closure`, `reviewer_root`, `security_review`, `code_review`, and `requirement_matrix` | FAIL CLOSED: `independent_review_artifact_drift:<artifact>` |
| Isolated copied-fixture mutations of archival and D-48 policy JSON | FAIL CLOSED: JSON parse/validation error before acceptance |

The isolated checks used a disposable checkout and disposable mutated copies only. They did not modify canonical evidence, policies, roots, the signed generation, or the index. The archival closure digest mismatch and legacy null-`subject` dereference remain open implementation/ceremony gaps; resolving them requires an additive authenticated archival update or a compatibility fix followed by the required signer ceremony. This interval therefore records operational observations only and cannot elevate Phase 1 status.

The prior gap interval above is preserved verbatim. The immutable CMS generation and `index.json` remain the sole authoritative D-48 closure; this derived note does not restate, alter, supersede, or override the signed review judgment. The legacy free-form `bundle.independent_review` object remains non-authoritative.
