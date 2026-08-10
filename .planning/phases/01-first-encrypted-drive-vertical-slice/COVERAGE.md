# External API and Service Coverage - Phase 1 Replan

Full coverage is the default. Every detected platform, service, and external boundary capability is classified below.

Binding execution roles:

- hungdinh-lt is the developer and Hyper-V orchestration machine only. Source checks and orchestration may run there, but endpoint evidence may not.
- LAB-DC01 runs the management server, PostgreSQL development database, trusted provisioning, primary AD checks, and trusted WinRM collection.
- LAB-DC02 independently supplies secondary AD corroboration.
- LAB-CLIENT01 runs every endpoint service, DPAPI, session, WinFsp, file, restart, and reboot verification.
- Every operation first asserts the actual computer name against the expected role. Sensitive values enter only through a runtime secret provider and never appear in this file, commands, evidence, or commits.

| capability | decision | reason |
|---|---|---|
| role.assert-computer-before-action | INTEGRATE | Plan 01-13 enforces this on all four machines before mutation or evidence collection |
| role.inventory-host-endpoint-residue | INTEGRATE | Plan 01-13 runs exact read-only inventory on hungdinh-lt |
| role.remove-verified-host-winfsp-runtime | INTEGRATE | Plan 01-13 removes only verified WinFsp runtime residue from hungdinh-lt |
| role.remove-verified-host-dlp-endpoint-artifacts | INTEGRATE | Plan 01-13 removes only exact DLP endpoint residue from hungdinh-lt |
| role.remove-host-developer-tools | OPT-OUT | D-20 requires Rust LLVM Hyper-V repositories and unrelated tools to remain |
| role.collect-endpoint-evidence-on-host | OPT-OUT | D-24 makes hungdinh-lt evidence invalid for endpoint requirements |
| postgres.start-development-database | INTEGRATE | Plan 01-13 starts PostgreSQL inside LAB-DC01 |
| postgres.apply-versioned-sqlx-migrations | INTEGRATE | Plan 01-13 applies checksummed forward migrations inside LAB-DC01 before listener bind |
| postgres.repeat-migrations-idempotently | INTEGRATE | Plan 01-13 proves repeated migration convergence inside LAB-DC01 |
| postgres.handle-concurrent-server-start | INTEGRATE | Plan 01-13 proves concurrent starters do not diverge inside LAB-DC01 |
| postgres.fail-on-migration-checksum-drift | INTEGRATE | Plan 01-13 proves failure before bind while preserving the prior LAB-DC01 database |
| postgres.persist-across-restart | INTEGRATE | Plan 01-13 proves Compose volume and authoritative state survive LAB-DC01 restart |
| postgres.automatic-production-seeding | OPT-OUT | ADR-003 forbids automatic production seed data |
| sqlite.isolated-unit-test-backend | INTEGRATE | SQLite remains permitted only in explicitly isolated tests on hungdinh-lt |
| sqlite.deployment-verification | OPT-OUT | SRV-11 and TST-05 require PostgreSQL evidence from LAB-DC01 |
| ad.primary-domain-computer-lookup | INTEGRATE | LAB-DC01 authenticates and validates the enrolled computer |
| ad.secondary-domain-computer-lookup | INTEGRATE | LAB-DC02 independently corroborates the same computer |
| ad.accept-single-authority-result | OPT-OUT | D-02 requires two-authority agreement before enrollment |
| winrm.kerberos-authenticated-cim-query | INTEGRATE | Trusted LAB-DC01 collects LAB-CLIENT01 hardware over WinRM HTTPS |
| winrm.basic-or-ntlm-collector-auth | OPT-OUT | The trusted collector requires Kerberos and cannot downgrade |
| windows.hardware-fingerprint-api | INTEGRATE | LAB-CLIENT01 service and LAB-DC01 collector use documented Windows APIs |
| windows.powershell-production-fingerprint | OPT-OUT | Plan 01-14 replaces the partial production PowerShell collector |
| http.live-readiness | INTEGRATE | LAB-CLIENT01 probes LAB-DC01 health live |
| http.dependency-readiness | INTEGRATE | LAB-CLIENT01 probes LAB-DC01 health ready after PostgreSQL migrations |
| http.admin-create-enrollment-token | INTEGRATE | Trusted provisioning executes on LAB-DC01 using admin mTLS |
| http.admin-register-fingerprint | INTEGRATE | Trusted provisioning binds the confirmed fingerprint on LAB-DC01 |
| http.admin-revoke-device | INTEGRATE | LAB-DC01 exposes authenticated device revocation |
| http.device-initial-enrollment | INTEGRATE | LAB-CLIENT01 submits token identity observation and CSR to LAB-DC01 |
| http.device-certificate-replacement | INTEGRATE | LAB-CLIENT01 replacement atomically revokes prior serial on LAB-DC01 |
| http.device-fetch-signed-configuration | INTEGRATE | LAB-CLIENT01 polls and validates current signed configuration |
| http.device-post-health | INTEGRATE | LAB-CLIENT01 posts redacted endpoint health to LAB-DC01 |
| http.device-post-audit-batch | INTEGRATE | LAB-CLIENT01 posts bounded redacted audit records to LAB-DC01 |
| http.unbounded-body-or-timeout | OPT-OUT | Plans 01-13 and 01-14 require bounded bodies and timeouts |
| tls.server-hostname-validation | INTEGRATE | LAB-CLIENT01 validates the ordinary LAB-DC01 hostname and public root |
| tls.dangerous-certificate-verifier | OPT-OUT | Plan 01-14 prohibits verifier bypasses |
| mtls.admin-client-identity | INTEGRATE | Trusted provisioning uses the distinct admin client profile on LAB-DC01 |
| mtls.endpoint-device-identity | INTEGRATE | LAB-CLIENT01 uses the distinct constrained device profile |
| mtls.bearer-fallback-after-enrollment | OPT-OUT | Device routes require mTLS after enrollment |
| pki.offline-root-public-trust | INTEGRATE | LAB-DC01 provisioning installs only approved public trust artifacts |
| pki.endpoint-private-ca-material | OPT-OUT | LAB-CLIENT01 never receives CA private material |
| dpapi.machine-scope-protect | INTEGRATE | LAB-CLIENT01 protects device credential and store key material |
| dpapi.machine-scope-unprotect | INTEGRATE | LAB-CLIENT01 service unprotects only after owner and DACL validation |
| dpapi.interactive-ui | OPT-OUT | The automatic service uses UI-forbidden DPAPI |
| scm.install-automatic-service | INTEGRATE | Plan 01-14 installs and verifies the service on LAB-CLIENT01 |
| scm.start-stop-shutdown | INTEGRATE | LAB-CLIENT01 exercises start stop shutdown force-kill and restart |
| scm.session-change-control | INTEGRATE | Plan 01-15 consumes sign-in and sign-out events on LAB-CLIENT01 |
| wts.enumerate-active-sessions | INTEGRATE | LAB-CLIENT01 service enumerates eligible interactive domain sessions |
| wts.obtain-primary-user-token | INTEGRATE | LAB-CLIENT01 derives immutable identity from TokenUser |
| createprocessasuser.launch-session-host | INTEGRATE | LAB-CLIENT01 launches the drive host into the captured user session |
| ipc.named-pipe-authenticated-storage | INTEGRATE | LAB-CLIENT01 validates SID session PID generation and pipe DACL |
| ipc.client-selects-identity-or-store | OPT-OUT | Identity and store selection remain service-owned |
| winfsp.install-official-runtime | INTEGRATE | Plan 01-15 verifies official pinned runtime only on LAB-CLIENT01 |
| winfsp.install-runtime-on-hungdinh-lt | OPT-OUT | D-20 forbids endpoint runtime on the developer host |
| winfsp.start-user-session-mount | INTEGRATE | LAB-CLIENT01 user host starts the approved WinFsp mount |
| winfsp.stop-user-session-mount | INTEGRATE | LAB-CLIENT01 drains cancels and unmounts at sign-out and service stop |
| winfsp.callback-create-open | INTEGRATE | Plan 01-15 binds create and open to authenticated encrypted storage |
| winfsp.callback-read-write-flush | INTEGRATE | Plan 01-15 binds data and durability callbacks to encrypted storage |
| winfsp.callback-rename-delete-cleanup-close | INTEGRATE | Plan 01-15 preserves operation and lifecycle semantics |
| winfsp.callback-directory-metadata-security | INTEGRATE | Plan 01-15 preserves enumeration metadata and security mapping |
| winfsp.kernel-filter-enforcement | OPT-OUT | The locked architecture is a user-mode WinFsp drive |
| hyperv.query-vm-state | INTEGRATE | hungdinh-lt validates all VM state before orchestration |
| hyperv.start-and-connect-vms | INTEGRATE | hungdinh-lt starts and reaches the assigned VMs |
| hyperv.invoke-guest-commands | INTEGRATE | hungdinh-lt dispatches commands that execute inside their named VMs |
| hyperv.hard-turnoff-lab-client01 | INTEGRATE | Plan 01-16 uses host-controlled abrupt loss for LAB-CLIENT01 only |
| hyperv.hard-turnoff-domain-controllers | OPT-OUT | Phase 1 abrupt-loss scope targets the endpoint and preserves AD authorities |
| office.word-com-file-roundtrip | INTEGRATE | Plan 01-16 executes Word inside the eligible LAB-CLIENT01 user session |
| office.excel-com-file-roundtrip | INTEGRATE | Plan 01-16 executes Excel inside the eligible LAB-CLIENT01 user session |
| shell.explorer-file-roundtrip | INTEGRATE | Plan 01-16 executes Explorer inside the eligible LAB-CLIENT01 user session |
| shell.notepad-file-roundtrip | INTEGRATE | Plan 01-16 executes Notepad inside the eligible LAB-CLIENT01 user session |
| network.modify-hosts-file | OPT-OUT | D-20 forbids DLP hosts mapping changes on hungdinh-lt |
| network.modify-domain-or-base-network | OPT-OUT | D-20 forbids DLP domain and base network changes on hungdinh-lt |

Coverage invariant: every INTEGRATE row has an owning replacement plan and binding execution machine. Every OPT-OUT row states a locked architecture, safety, or phase-boundary reason.
