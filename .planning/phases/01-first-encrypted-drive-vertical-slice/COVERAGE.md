# API Coverage — Phase 1 External Integrations

> Full coverage by default. Opt-outs are explicit, reasoned decisions. Capability names are prefixed because AD, WinFsp, and the management-server HTTP surface are independently evaluated integrations.

Revised plan ownership: AD authority is implemented in `01-06`; authenticated HTTP/TLS/readiness in `01-07`; real WinFsp host/callback coverage in `01-10`; final production-provider evidence in `01-12`. The decisions below are unchanged by plan splitting.

| capability | decision | reason |
|---|---|---|
| ad.ldaps-server-identity-validation | INTEGRATE | |
| ad.bind-with-dedicated-read-credential | INTEGRATE | |
| ad.query-primary-dc-directly | INTEGRATE | |
| ad.query-secondary-dc-directly | INTEGRATE | |
| ad.lookup-computer-by-configured-domain-and-name | INTEGRATE | |
| ad.read-object-guid | INTEGRATE | |
| ad.read-object-sid | INTEGRATE | |
| ad.read-enabled-account-state | INTEGRATE | |
| ad.read-dns-host-name | INTEGRATE | |
| ad.require-two-dc-identity-agreement | INTEGRATE | |
| ad.timeout-and-fail-closed | INTEGRATE | |
| ad.follow-referrals | OPT-OUT | Phase 1 queries two explicitly configured authoritative DC endpoints and fails closed instead of trusting a referral target. |
| ad.directory-mutation | OPT-OUT | Enrollment requires read-only identity corroboration; allowlist and credential state are managed in PostgreSQL. |
| ad.group-policy-and-user-directory-queries | OPT-OUT | Phase 1 authenticates the computer account only; user policy and groups are outside this enrollment surface. |
| winfsp.delay-load-linking | INTEGRATE | |
| winfsp.host-create-start-mount-stop | INTEGRATE | |
| winfsp.per-session-drive-letter-mount | INTEGRATE | |
| winfsp.volume-information | INTEGRATE | |
| winfsp.security-by-name | INTEGRATE | |
| winfsp.open-and-create | INTEGRATE | |
| winfsp.cleanup-and-close | INTEGRATE | |
| winfsp.read-and-write | INTEGRATE | |
| winfsp.flush | INTEGRATE | |
| winfsp.get-file-information | INTEGRATE | |
| winfsp.set-basic-information | INTEGRATE | |
| winfsp.set-file-size-and-truncate | INTEGRATE | |
| winfsp.rename-and-replace | INTEGRATE | |
| winfsp.can-delete-and-delete | INTEGRATE | |
| winfsp.read-directory-and-create-directory | INTEGRATE | |
| winfsp.share-mode-and-delete-pending-semantics | INTEGRATE | |
| winfsp.explicit-cancellation-on-sign-out | INTEGRATE | |
| winfsp.named-streams | OPT-OUT | The Phase 1 file corpus does not require alternate data streams and the encrypted format has no ADS contract. |
| winfsp.hard-links | OPT-OUT | The Phase 1 store models one file identity per directory entry; hard-link aliasing is not part of the protected-drive contract. |
| winfsp.reparse-points | OPT-OUT | Reparse traversal would cross the protected-store boundary and is denied for this phase. |
| winfsp.sparse-files | OPT-OUT | Sparse allocation semantics are not required by the D-16 through D-18 application and size matrix. |
| winfsp.extended-attributes | OPT-OUT | The selected Windows application matrix does not require arbitrary extended attributes; security and timestamps use explicit callbacks. |
| winfsp.kernel-driver-development | OPT-OUT | The product constraint requires the installed WinFsp runtime and prohibits a custom kernel driver. |
| http.post-admin-device-allowlist | INTEGRATE | |
| http.post-admin-enrollment-token | INTEGRATE | |
| http.post-agent-enroll | INTEGRATE | |
| http.get-agent-configuration | INTEGRATE | |
| http.post-agent-health | INTEGRATE | |
| http.get-health-live | INTEGRATE | |
| http.get-health-ready | INTEGRATE | |
| http.admin-bearer-authentication | INTEGRATE | |
| http.agent-mtls-authentication | INTEGRATE | |
| http.request-size-timeout-and-json-validation | INTEGRATE | |
| http.http1-and-http2 | INTEGRATE | |
| http.configuration-push-sse | OPT-OUT | ADR-002 selects agent polling and heartbeat for the initial synchronization model. |
| http.policy-authoring-and-assignment | OPT-OUT | Phase 2 owns policy authoring, validation, assignment, publication, and deployment controls. |
| http.event-batch-upload | OPT-OUT | Phase 3 owns ordered idempotent event synchronization. |
| http.fleet-lock-revoke-retire-admin-routes | OPT-OUT | Phase 3 owns fleet lifecycle administration; Phase 1 only performs credential replacement revocation required by D-06. |
| http.audit-search-and-export | OPT-OUT | Phase 3 owns audit search and export. |
| http.websocket-and-grpc-transports | OPT-OUT | ADR-002 fixes REST-style JSON over HTTP/1.1 and HTTP/2 for the MVP. |
