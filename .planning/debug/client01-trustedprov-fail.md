---
slug: client01-trustedprov-fail
status: awaiting_human_verify
trigger: All settle but still failed Invoke-Client01Runtime.ps1 with TrustedProvisioning
created: 2026-08-14
updated: 2026-08-15
---

## Current Focus

- hypothesis: The server advertised HTTP/2 via ALPN but axum was compiled without the http2 feature, so the HTTP/2 preface from reqwest caused hyper-util to close the connection after the TLS handshake.
- test: Enabled axum http2 feature in dlp-server/Cargo.toml and added ALPN logging in RustlsListener::accept. Verified with cargo check and cargo test.
- expecting: The next end-to-end run on LAB-DC01 will show `negotiated alpn=h2` in tls-events.log, the route handler will log `require_administrator` and `admin_provisioning_contract`, and dlpctl will receive an HTTP 200 with the enrollment token.
- next_action: Request human verification on LAB-DC01: stop dlp-server, run Invoke-Client01Runtime.ps1 -Scenario Tracer -EnrollmentTokenProvider TrustedProvisioning -Apply, then share tls-events.log, dlp-server.err, dlpctl.err, dlpctl-rust.err, and the enrollment token result.

## Symptoms

- **Expected behavior**: Provisioning succeeds — dlpctl should authenticate as the provisioning admin and obtain an enrollment token from the management server.
- **Actual behavior**: dlpctl exits with code 1. The server logs show repeated TLS handshake EOF errors from both 127.0.0.1 and 192.168.50.10. The dlpctl stderr shows `Error: TrustedStationRequired` and a lower-level `provisioning POST failed: error sending request for url (https://lab-dc01.lab.local:8443/api/v1/admin/provisioning)` caused by `client error (SendRequest)` → `connection error` → `connection aborted`.
- **Error messages**:
  - `Error: TrustedStationRequired`
  - `provisioning POST failed: error sending request for url (https://lab-dc01.lab.local:8443/api/v1/admin/provisioning)`
  - `caused by: client error (SendRequest)`
  - `caused by: connection error`
  - `caused by: connection aborted`
  - `tls accept failed from ...: tls handshake eof`
- **Timeline**: Always failed for this exact flow; never completed successfully.
- **Reproduction**: Re-run `Invoke-Client01Runtime.ps1` with `-EnrollmentTokenProvider TrustedProvisioning`.

## Eliminated

- hypothesis: Server is not running.
  reason: The script installs the binary, runs migrations, and starts the server; the failure occurs while the server is listening and producing TLS logs.

- hypothesis: The latest failure is a TLS/certificate error.
  reason: Fresh dlpctl diagnostics show the process fails in `collect_from_trusted_station` before `ProvisioningClient::new` or `provision` is reached. The TLS errors were stale artifacts from earlier runs and TCP readiness probes.

- hypothesis: The disk-serial/trusted-station collector is still failing.
  reason: Human verification confirms the collector now succeeds and the new failure is a clean TLS/transport error after `ProvisioningClient::provision` is reached.

- hypothesis: `DLP_PROVISIONING_ROOT_CA_PEM` is stale and dlpctl trusts the wrong root.
  reason: Diagnostic snapshot shows `provisioning_root_matches_secrets_root: true` and the SHA256 matches the current on-disk root. Server cert issuer matches the current root subject.

- hypothesis: Server cert hostname/SAN mismatch or missing server-auth EKU/KU.
  reason: Local inspection of the rotated cert (whose root hash matches LAB-DC01) shows SAN includes `DNS:LAB-DC01.lab.local`, EKU includes `serverAuth`, and Key Usage includes `digitalSignature`/`keyEncipherment`. Verify-DlpLabCertificates.ps1 passed these checks against the live files.

- hypothesis: dlpctl's TLS handshake aborts because reqwest 0.13's default rustls platform verifier rejects the self-signed Phase 1 root CA supplied via add_root_certificate.
  reason: rustls trace logging shows the handshake reaches ServerHello, EncryptedExtensions, and CertificateRequest, then resets with no InvalidCertificate error. The client is failing at client-certificate selection, not server-certificate validation. The previous tls_certs_only change is therefore not the fix.

- hypothesis: Client-certificate selection fails because the provisioning admin identity chain lacks the issuing CA.
  reason: After appending the admin CA to the identity chain, rustls reaches "Attempting client auth" after the server cert, and the server logs `verify_client_cert accepted`. The chain is now selected and verified, so the omission issue is resolved.

- hypothesis: The C:\dlp\secrets\*.pem files are corrupted with path strings.
  reason: Human verification confirms all secrets/provisioning files now contain valid PEM content and the server loaded the trust anchors successfully.

- hypothesis: The post-handshake reset is caused by a handler panic or database error.
  reason: No [routes] logs appear in dlp-server.err, and the dlpctl error is a transport-level connection reset, not an HTTP error status. A handler/database error would return UNAUTHORIZED/BAD_REQUEST and be visible in route logs.

## Evidence

- timestamp: 2026-08-14
  source: user-provided failure output
  observation: Server readiness diagnostics show `process_running=false`, `port_listening=false`, `tcp_connect_succeeded=false` before the script installs the binary and starts the server. After installation, secret validation reports `admin-ca.pem` mismatch (`expected` vs `actual` differ) in the initial probe, but a later validation only checks `phase1-root-ca.pem`, `server-cert.pem`, and `server-key.pem`.
- timestamp: 2026-08-14
  source: dlp-server/src/tls.rs
  observation: Server uses `WebPkiClientVerifier::builder(...).allow_unauthenticated()` so the TLS handshake can complete without a client certificate. Admin routes require `AuthenticatedAdmin` derived from the TLS peer certificate. The peer identity issuer must match `DLP_ADMIN_CA_CERT_PEM` for administrator role.
- timestamp: 2026-08-14
  source: dlpctl/src/main.rs
  observation: dlpctl `ProvisioningClient::new` loads the root CA as a trusted anchor, loads the provisioning admin cert+key as a reqwest `Identity`, and POSTs to the provisioning endpoint. Missing env vars or invalid hex for GUID/SID return `TrustedStationRequired`; client construction/transport errors return `ProvisioningApiUnavailable`.
- timestamp: 2026-08-14
  source: scripts/lab/Invoke-Client01Runtime.ps1
  observation: `Update-DlpEnvironmentFromRotatedFiles` updates provisioning-admin-cert/key from `C:\dlp\secrets\`. `Assert-Client01ServerReady` includes `admin-ca.pem` in its remote hash check and the reported diagnostics showed a mismatch for that file, indicating the server's trust anchor for admin client certs is stale or different from the orchestrator's.
- timestamp: 2026-08-14
  source: openssl inspection of target/01-07-pki/server-cert.pem
  observation: Server certificate subject is `CN=management.test.local`, issuer is `CN=DLP Phase 1 Test Root`, and SAN contains only `DNS:management.test.local`. The provisioning endpoint is `https://lab-dc01.lab.local:8443/api/v1/admin/provisioning`, so the server's DNS identity does not match the hostname dlpctl validates.
- timestamp: 2026-08-14
  source: dlpctl/src/lib.rs and reqwest behavior
  observation: dlpctl `ProvisioningClient` uses reqwest with `.https_only(true)` and `.add_root_certificate(root_certificate)`. reqwest/rustls performs TLS hostname verification against the endpoint URL's host (`lab-dc01.lab.local`). A mismatched SAN causes the client to abort the handshake, which the server logs as `tls handshake eof`.
- timestamp: 2026-08-14
  source: PowerShell parser syntax check
  observation: `[System.Management.Automation.PSParser]::Tokenize` on the modified `Invoke-Client01Runtime.ps1` returned no parse errors (`SYNTAX OK`).
- timestamp: 2026-08-14
  source: script inspection
  observation: `Assert-Client01CertificatesValid` is defined at line 610 and invoked at the top of `Assert-Client01ServerReady` at line 634. It calls `scripts/lab/Verify-DlpLabCertificates.ps1 -ServerHostname '$ProbeMachine.lab.local'`.
- timestamp: 2026-08-14
  source: openssl + Verify-DlpLabCertificates.ps1 logic
  observation: The existing verification script checks `server_cert_hostname_mismatch` by comparing the server cert's SANs/CN to `-ServerHostname`. The current fixture cert (`management.test.local`) would fail this check against `LAB-DC01.lab.local`.
- timestamp: 2026-08-14
  source: human verification checkpoint response
  observation: After the server cert hostname/SAN fix, `Verify-DlpLabCertificates.ps1` now fails with `missing_key_cert_sign:admin CA`. The admin CA has Basic Constraints CA:True but Key Usage keyCertSign: False. The server cert subject is now `O=DLP Lab, CN=LAB-DC01.lab.local`, so the prior hostname mismatch is resolved.
- timestamp: 2026-08-14
  source: .planning/docs/PEM-KEY-GUIDE.md section 3a
  observation: The documented admin CA generation uses `openssl req -x509 ... -subj '/CN=admin-ca/O=DLP Lab' -out admin-ca.pem` with no `-extensions v3_ca` and no Key Usage extension, which produces a CA certificate that rustls/webpki rejects as a trust anchor.
- timestamp: 2026-08-14
  source: scripts/lab/Rotate-DlpAdminCa.ps1
  observation: The rotation script already generates a compliant admin CA with `basicConstraints = critical, CA:true` and `keyUsage = critical, digitalSignature, cRLSign, keyCertSign`, and reissues the provisioning-admin certificate with `digitalSignature` + `clientAuth`.
- timestamp: 2026-08-14
  source: local openssl reproduction of updated PEM-KEY-GUIDE.md commands
  observation: Generated admin-ca.pem shows `Basic Constraints: critical, CA:TRUE` and `Key Usage: critical, Digital Signature, Certificate Sign, CRL Sign`. Generated provisioning-admin-cert.pem shows `Key Usage: Digital Signature` and `Extended Key Usage: TLS Web Client Authentication`. `openssl verify` chains successfully.
- timestamp: 2026-08-14
  source: human verification checkpoint response after Rotate-DlpAdminCa.ps1 -Force
  observation: Admin CA now has Basic Constraints CA:True and Key Usage keyCertSign:True. Verify-DlpLabCertificates.ps1 now fails with `signature_verification_failed:server cert`. Server cert subject/issuer are `O=DLP Lab, CN=LAB-DC01.lab.local` / `O=DLP Lab, CN=phase1-root-ca`. The signature cannot be verified against the current phase1-root-ca, indicating the server cert was signed by a different/older root or the root was rotated without reissuing the server cert. Device issuing CA still lacks Key Usage keyCertSign (warned but not fatal).
- timestamp: 2026-08-14
  source: openssl inspection of target/01-07-pki fixtures
  observation: Fixture server cert has subject CN=management.test.local issued by CN=DLP Phase 1 Test Root, SAN only DNS:management.test.local. Fixture device-issuing-ca.pem has Basic Constraints CA:TRUE and Key Usage Certificate Sign. The live lab files differ (O=DLP Lab naming, device CA missing keyCertSign), confirming deployed artifacts are not the fixtures.
- timestamp: 2026-08-14
  source: scripts/lab/Invoke-Client01Runtime.ps1 and Invoke-Dc01Server.ps1
  observation: Both scripts deploy server-cert.pem, server-key.pem, admin-ca.pem, phase1-root-ca.pem, device-issuing-ca.pem, and device-issuing-ca-key.pem to C:\dlp\secrets\ on LAB-DC01 from environment variables. Update-DlpEnvironmentFromRotatedFiles only handles admin-ca and provisioning-admin-cert/key, so rotated server-cert or device-issuing-ca files are not automatically picked up if the env var points elsewhere or contains inline PEM.
- timestamp: 2026-08-14
  source: scripts/lab/PEM-KEY-GUIDE.md sections 2 and 4
  observation: The guide already documents correct generation of server cert (SAN includes LAB-DC01, LAB-DC01.lab.local, 192.168.50.10; EKU serverAuth) and device-issuing-ca with v3_ca extensions including keyCertSign. No documentation change is required; the issue is operational stale/mismatched deployed files.
- timestamp: 2026-08-14
  source: local test of Rotate-DlpServerCert.ps1 and Rotate-DlpDeviceIssuingCa.ps1
  observation: Generated server cert (CN=LAB-DC01.lab.local, O=DLP Lab) chains to a temp phase1-root-ca, has SAN DNS:LAB-DC01, DNS:LAB-DC01.lab.local, IP:192.168.50.10, EKU serverAuth, and Key Usage digitalSignature/keyEncipherment. Generated device-issuing-ca has Basic Constraints CA:TRUE and Key Usage Certificate Sign. A full run of Verify-DlpLabCertificates.ps1 against all rotated files reported "All certificate/key checks passed".
- timestamp: 2026-08-14
  source: local openssl inspection of C:\dlp\secrets\phase1-root-ca.pem and phase1-root-ca-key.pem
  observation: The on-disk root CA cert and key have identical RSA moduli, confirming they are a matched pair. The certificate subject is CN=phase1-root-ca, O=DLP Lab, signed with sha256WithRSAEncryption, 4096-bit key, valid from 2026-08-14.
  implication: The physical lab files are consistent; the mismatch is introduced by the script's source selection, not by corrupt files.
- timestamp: 2026-08-14
  source: environment variable inspection
  observation: `$env:DLP_PHASE1_ROOT_CA_CERT_PEM` is set to an inline PEM certificate whose subject is `CN=DLP Phase 1 Test Root` and whose public key algorithm is EC (`prime256v1`). `$env:DLP_PHASE1_ROOT_CA_KEY_PEM` is empty, so the script falls back to `C:\dlp\secrets\phase1-root-ca-key.pem`, an RSA key.
  implication: Rotate-DlpServerCert.ps1 mixed an EC cert with an RSA key, which is why OpenSSL reported `key values mismatch`.
- timestamp: 2026-08-14
  source: code inspection of Rotate-DlpServerCert.ps1
  observation: The script resolves the root CA cert from the env var via `Resolve-PemContent`, but resolves the root CA key from the env var if present or from `-RootCaKeyPath` otherwise. There is no `-RootCaCertPath` parameter and no validation that the resolved cert and key correspond.
  implication: A stale inline cert env var paired with a file key will always cause an opaque OpenSSL failure. The script should validate the pair and fall back to the canonical on-disk pair when mismatched.
- timestamp: 2026-08-14
  source: local run of Rotate-DlpServerCert.ps1 -Force after fix
  observation: The script detected the mismatched env-var cert/file key, emitted a warning, fell back to the canonical C:\dlp\secrets\phase1-root-ca.pem / phase1-root-ca-key.pem pair, and produced a new server cert with subject O=DLP Lab, CN=LAB-DC01.lab.local that chains to the current root.
  implication: The rotation script now tolerates a stale inline root CA cert env var and still uses the correct matching pair.
- timestamp: 2026-08-14
  source: local run of Rotate-DlpDeviceIssuingCa.ps1 -Force
  observation: The script self-signed a new device-issuing CA with Basic Constraints CA:TRUE and Key Usage Certificate Sign. It does not reference an external root CA cert/key pair, so it cannot suffer the same mixed-pair failure as Rotate-DlpServerCert.ps1.
  implication: No equivalent fix is needed for the device CA rotation script.
- timestamp: 2026-08-14
  source: local run of Verify-DlpLabCertificates.ps1 -ServerHostname LAB-DC01.lab.local after fixes
  observation: After extending the verification script's rotated-file pickup and fixing the key/cert modulus comparison to use the original PEM strings, all checks passed: server cert hostname, chain signature, CA keyCertSign, client cert EKU, key/modulus matches, and RSA key sizes.
  implication: The PKI material is now consistent and ready for the full Invoke-Client01Runtime.ps1 run.
- timestamp: 2026-08-14
  source: code inspection of Verify-DlpLabCertificates.ps1
  observation: The script used `$Cert.ExportCertificatePem()` to re-obtain PEM for modulus comparison, but `X509Certificate2` does not expose that method in this environment, causing `Method invocation failed`.
  implication: The script should pass the original cert PEM string directly to `Get-OpensslModulus` instead of re-exporting.
- timestamp: 2026-08-14
  source: human verification checkpoint response
  observation: After the latest script fixes, all structural checks pass (admin CA keyCertSign, device issuing CA keyCertSign, provisioning admin EKU, modulus matches for all key pairs). However, `Verify-DlpLabCertificates.ps1` still fails with `signature_verification_failed:server cert`. Server cert subject/issuer are `O=DLP Lab, CN=LAB-DC01.lab.local` / `O=DLP Lab, CN=phase1-root-ca`. Chain status reports the signature cannot be verified and the root is not trusted by the trust provider.
  implication: The server cert in `C:\dlp\secrets` was signed by a previous `phase1-root-ca` key. The current on-disk `phase1-root-ca.pem`/`phase1-root-ca-key.pem` are a new matched pair with the same subject DN, so issuer names match but the signature does not. A server-cert re-rotation against the current root is required.

- timestamp: 2026-08-14
  source: dlpctl/src/main.rs error mapping
  observation: `TrustedStationRequired` is only returned when `provisioning::collect_from_trusted_station` fails or a required `DLP_PROVISIONING_*` environment variable is missing. `ProvisioningClient::new` and `ProvisioningClient::provision` failures map to `ProvisioningApiUnavailable`.
  implication: A current `dlpctl.err` ending in `TrustedStationRequired` means the latest run never reached the TLS/HTTP provisioning request; the `dlpctl-rust.err` TLS error is from a previous run unless it was overwritten in the same run.
- timestamp: 2026-08-14
  source: scripts/lab/Invoke-TrustedProvisioning.ps1
  observation: The script removes `dlpctl.err` and `dlpctl.log` before invoking `dlpctl` but does not remove `dlpctl-rust.err`. The diagnostic file is written by `ProvisioningClient::provision` only when a transport error occurs.
  implication: A stale `dlpctl-rust.err` from an earlier TLS failure can survive and be reported alongside a current, unrelated `TrustedStationRequired` failure.
- timestamp: 2026-08-14
  source: dlpctl/src/main.rs provisioning::collect_from_trusted_station
  observation: The CIM collector discards the PowerShell stderr and stdout when the child process exits non-zero, returning a generic `Err(())`.
  implication: Any CIM/WinRM/Kerberos/disk-normalization failure is hidden behind `TrustedStationRequired`; the underlying error must be surfaced to diagnose the current failure.
- timestamp: 2026-08-14
  source: scripts/lab/Invoke-Client01Runtime.ps1 Assert-Client01ServerReady
  observation: The readiness probe opens a plain TCP connection to `127.0.0.1:$Port` and immediately closes it. The server `RustlsListener` will then log a TLS accept failure because it attempts a TLS handshake on a connection that was closed before ClientHello.
  implication: The `127.0.0.1` handshake-EOF entry in `tls-events.log` is expected from the readiness probe, not evidence of a dlpctl TLS failure.
- timestamp: 2026-08-14
  source: dlpctl/src/lib.rs ProvisioningClient::new
  observation: The client loads the root CA from the path supplied by `DLP_PROVISIONING_ROOT_CA_PATH`, builds a reqwest `Identity` by concatenating the provisioning admin cert and key PEMs, validates the endpoint host is an HTTPS FQDN, and uses `https_only(true)`.
  implication: There is no obvious code defect in the client TLS construction; the failure is upstream (collector) or downstream (stale trust anchor/identity that would produce `ProvisioningApiUnavailable`, not `TrustedStationRequired`).

- timestamp: 2026-08-14
  source: human verification checkpoint response
  observation: Fresh diagnostics from LAB-DC01 show the dlpctl collector stderr: `physical disk serial missing` thrown at the line `if($mode -ne 'lab-only'){throw 'physical disk serial missing'}`. The collector stdout is empty and dlpctl reports `Error: TrustedStationRequired`.
  implication: The embedded PowerShell collector is running in `production` mode because `DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID` is not set to `true` for the dlpctl process. This is the immediate cause of the current failure.

- timestamp: 2026-08-14
  source: crates/dlpctl/src/main.rs Command::ProvisionDevice
  observation: `let lab_mode = env::var("DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID").ok().as_deref() == Some("true");` then `provisioning::collect_from_trusted_station(&computer, lab_mode)`. The collector script uses `$mode=$env:DLP_PROVISIONING_DISK_MODE` and throws `physical disk serial missing` when the serial is empty and mode is not `lab-only`.
  implication: dlpctl strictly requires the exact env var `DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID=true` to enter lab-only disk mode.

- timestamp: 2026-08-14
  source: scripts/lab/Invoke-TrustedProvisioning.ps1
  observation: The script sets `DLP_PROVISIONING_*` env vars (endpoint, root CA, admin cert/key, token handoff path, diagnostic path) before `Start-Process dlpctl`, but it never sets `DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID`. Its own CIM collection already accepts `Win32_DiskDrive.PNPDeviceID` when the physical serial is invalid, confirming the lab runs on virtual disks.
  implication: The script must explicitly opt the dlpctl child process into lab virtual-disk mode, because the default (production) is invalid for Hyper-V VMs.

- timestamp: 2026-08-14
  source: scripts/lab/Invoke-Client01Runtime.ps1 Invoke-Client01TrustedProvisioning
  observation: The orchestrator attempts to forward `$env:DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID` into the remote LAB-DC01 session only when it is non-empty on the orchestrator. It then relies on inheritance through `& scripts/lab/Invoke-TrustedProvisioning.ps1` and `Start-Process`.
  implication: The env var can be lost if the orchestrator does not export it or if the nested invocation does not inherit it. Setting the flag directly in Invoke-TrustedProvisioning.ps1 removes both dependencies.

- timestamp: 2026-08-14
  source: scripts/lab/Set-DlpEnvironment.ps1 and Initialize-DlpEnvironment.ps1
  observation: `DLP_LAB_ALLOW_VIRTUAL_DISK_UNIQUE_ID = 'true'` is part of the documented lab environment defaults.
  implication: The intended lab behavior is virtual-disk mode; the trusted-provisioning script just needs to apply that intent at the dlpctl invocation boundary.

- timestamp: 2026-08-14
  source: scripts/lab/Invoke-Client01Runtime.ps1
  observation: `Update-DlpEnvironmentFromRotatedFiles` refreshes `DLP_PHASE1_ROOT_CA_CERT_PEM`, `DLP_ADMIN_CA_CERT_PEM`, `DLP_PROVISIONING_ADMIN_CERT_PEM`, etc., but does NOT refresh `DLP_PROVISIONING_ROOT_CA_PEM` or `DLP_PROVISIONING_ROOT_CA_PATH`. `Invoke-Client01TrustedProvisioning` prefers `DLP_PROVISIONING_ROOT_CA_PEM`/`PATH` over `DLP_PHASE1_ROOT_CA_CERT_PEM` when selecting the root CA to pass to dlpctl.
  implication: A stale `DLP_PROVISIONING_ROOT_CA_PEM` (e.g., the old inline EC cert from earlier fixtures) will be passed to dlpctl even after `DLP_PHASE1_ROOT_CA_CERT_PEM` was corrected. `Verify-DlpLabCertificates.ps1` would pass if it falls back to `DLP_PHASE1_ROOT_CA_CERT_PEM`, but dlpctl would still trust the wrong root.

- timestamp: 2026-08-14
  source: scripts/lab/Invoke-Client01Runtime.ps1
  observation: `Invoke-Client01TrustedProvisioning` builds `$provisioningRootCa` from `DLP_PROVISIONING_ROOT_CA_PEM`/`PATH` if either is set, otherwise from `DLP_PHASE1_ROOT_CA_CERT_PEM`. It then passes this inline PEM to the remote LAB-DC01 session, where `Invoke-TrustedProvisioning.ps1` writes it to `C:\dlp\provisioning\phase1-root-ca.pem` for dlpctl to load.
  implication: If the selected root PEM differs from the root that signed the server cert deployed to `C:\dlp\secrets\server-cert.pem`, dlpctl will abort the TLS handshake because it cannot validate the server identity.

- timestamp: 2026-08-14
  source: dlp-server/src/tls.rs RustlsListener::accept
  observation: The server logs three distinct outcomes after the TLS accept: (1) `tls accept failed` if rustls rejects the handshake (invalid client cert, protocol issue, etc.); (2) `tls peer identity rejected` if the handshake succeeds but the leaf issuer does not match the configured admin/device CAs; (3) `tls connection ... completed without client certificate` for unauthenticated connections.
  implication: A fresh `tls-events.log` will reveal whether the abort is a client-side validation failure (client sends alert/EOF) or a server-side rejection.

- timestamp: 2026-08-14
  source: created scripts/lab/Debug-TrustedProvisioningTls.ps1
  observation: A standalone diagnostic script now exists that snapshots the env vars, hashes, and PEM subjects of `C:\dlp\provisioning\*` vs `C:\dlp\secrets\*`, clears `tls-events.log`, and optionally runs `openssl s_client` against the server using the provisioning root.
  implication: Running this immediately before reproducing the failure will produce a single JSON report that distinguishes the four candidate causes listed in the human-verify response.

- timestamp: 2026-08-14
  source: human verification checkpoint response (diagnostic snapshot)
  observation: |
    Diagnostic JSON shows `DLP_PROVISIONING_ROOT_CA_PEM` is reported as `<not-set>` in the diagnostic context, but `provisioning_root_matches_secrets_root: true` and both SHA256 equal the local `tmp/phase1-root-ca.pem` hash (`988b4ae...`). Server cert subject is `CN=LAB-DC01.lab.local, O=DLP Lab` and issuer is `CN=phase1-root-ca, O=DLP Lab`.
  implication: The provisioning root CA is not stale; the server is presenting the rotated cert signed by the current root. The earlier "stale root CA" hypothesis is disproven.

- timestamp: 2026-08-14
  source: dlpctl.err / dlpctl-rust.err from checkpoint
  observation: |
    dlpctl now exits with `Error: ProvisioningApiUnavailable`. `dlpctl-rust.err` shows:
    ```
    provisioning POST failed: error sending request for url (https://lab-dc01.lab.local:8443/api/v1/admin/provisioning)
      caused by: client error (SendRequest)
      caused by: connection error
      caused by: connection reset
    ```
  implication: The trusted-station collector/lab-mode issue is resolved; dlpctl reaches `ProvisioningClient::provision`. The remaining failure is at the TLS/transport layer, but reqwest's error chain only reports a generic TCP reset, not the underlying rustls rejection.

- timestamp: 2026-08-14
  source: fresh tls-events.log from checkpoint
  observation: |
    Two entries after reproduction:
    ```
    [1786727297.626] tls accept failed from 127.0.0.1:51949: tls handshake eof
    [1786727304.140] tls accept failed from 192.168.50.10:51960: tls handshake eof
    ```
  implication: The 127.0.0.1 entry is the orchestrator's plain-TCP readiness probe. The 192.168.50.10 entry is dlpctl. In both cases the peer closed the connection during the TLS handshake (EOF), which is consistent with a client-side rustls certificate/validation rejection.

- timestamp: 2026-08-14
  source: local openssl inspection of tmp/*.pem (hashes match LAB-DC01 root)
  observation: |
    `tmp/phase1-root-ca.pem` SHA256 matches the diagnostic value. Full text shows:
    - Root CA: Basic Constraints CA:TRUE (critical), Key Usage Digital Signature / Certificate Sign / CRL Sign (critical), SKID/AKID present, sha256WithRSAEncryption, 4096-bit RSA.
    - Server cert: SAN DNS:LAB-DC01, DNS:LAB-DC01.lab.local, IP:192.168.50.10; EKU serverAuth; Key Usage digitalSignature, keyEncipherment (critical); signed by root.
    - Admin CA: Basic Constraints CA:TRUE, Key Usage includes keyCertSign.
    - Provisioning admin cert: Key Usage digitalSignature (critical), EKU clientAuth, issuer admin-ca.
  implication: All inspected certificates satisfy the documented rustls/webpki requirements. The abort is not caused by an obvious missing extension or hostname mismatch in the rotated fixture files.

- timestamp: 2026-08-15
  source: reqwest 0.13.4 source code (local registry)
  observation: When `tls_certs_only` is false and `root_certs` is not empty, reqwest builds a rustls `ClientConfig` using `rustls_platform_verifier::Verifier::new_with_extra_roots`. When `tls_certs_only` is true, it uses `config_builder.with_root_certificates(rustls_store(...))`, i.e. a pure webpki verifier.
  implication: The dlpctl code path (`add_root_certificate`) triggers the platform verifier. A self-signed Phase 1 root may be rejected or ignored by the Windows platform verifier, producing a client-side handshake abort.

- timestamp: 2026-08-15
  source: web search / seanmonstar/reqwest issue #2941
  observation: In reqwest 0.13, `add_root_certificate` behavior changed with the rustls backend; self-signed certificates added this way can fail with `InvalidCertificate(UnknownIssuer)`. The recommended replacement is `tls_certs_only()` or `tls_certs_merge()`.
  implication: This matches our symptoms exactly and points to a code fix rather than a certificate generation problem.

- timestamp: 2026-08-15
  source: human verification checkpoint response (rustls trace)
  observation: |
    rustls trace logging shows the handshake reaches TLS 1.3 ServerHello, EncryptedExtensions, and a CertificateRequest. The server sends `authority_names` for both `admin-ca` and `device-issuing-ca`. Immediately after, the connection is reset. There is no rustls `InvalidCertificate` error logged. The trace ends right after `Attempting client auth`.
  implication: The client is failing at client-certificate selection, not server-certificate validation. The previous platform-verifier hypothesis is disproven. The cause is either missing intermediate CA in the identity chain, stale/wrong provisioning-admin cert material, or a cert that does not match the requested authority_names.

- timestamp: 2026-08-15
  source: code changes to dlpctl/src/lib.rs
  observation: Added optional `provisioning_admin_ca_pem_path: Option<&Path>` to `ProvisioningClient::new`. When present, the admin CA PEM is appended to the cert chain before `Identity::from_pem(chain)`. Added eprintln diagnostics for loaded PEM sizes and identity build success/failure.
  implication: dlpctl can now present the full leaf + issuing CA chain to the server, and any cert/identity construction errors will be visible in dlpctl.err.

- timestamp: 2026-08-15
  source: code changes to dlpctl/src/main.rs
  observation: Reads optional `DLP_PROVISIONING_ADMIN_CA_CERT_PATH` environment variable and passes it to `ProvisioningClient::new`.
  implication: The orchestrator can supply the admin-ca cert path without changing dlpctl's CLI interface.

- timestamp: 2026-08-15
  source: code changes to Invoke-TrustedProvisioning.ps1
  observation: Added mandatory `AdminCaPem` parameter, writes `admin-ca.pem` to the provisioning directory, and sets `DLP_PROVISIONING_ADMIN_CA_CERT_PATH` for dlpctl.
  implication: dlpctl on LAB-DC01 receives the issuing CA alongside the leaf cert and key.

- timestamp: 2026-08-15
  source: code changes to Invoke-Client01Runtime.ps1
  observation: Resolves `DLP_ADMIN_CA_CERT_PEM` and passes it through to the remote `Invoke-TrustedProvisioning.ps1` invocation as `-AdminCaPem`.
  implication: The admin CA used by the server is the same one supplied to dlpctl for chain construction.

- timestamp: 2026-08-15
  source: code changes to Debug-TrustedProvisioningTls.ps1
  observation: Added provisioning-admin cert analysis including issuer, subject, clientAuth EKU, digitalSignature KU, signature verification against both provisioning and secrets admin-ca, and key/cert modulus comparison. Also includes admin-ca subject comparison.
  implication: The diagnostic snapshot will now distinguish chain omission from stale cert material.

- timestamp: 2026-08-15
  source: cargo check / cargo test -p dlpctl --lib
  observation: `cargo check -p dlpctl` and `cargo test -p dlpctl --lib` both pass (5 tests passed).
  implication: The Rust changes compile and the existing unit tests still pass.

- timestamp: 2026-08-15
  source: PowerShell parser syntax check
  observation: `Invoke-TrustedProvisioning.ps1`, `Invoke-Client01Runtime.ps1`, and `Debug-TrustedProvisioningTls.ps1` all report `SYNTAX OK` via PSParser (the Tokenize overload error in the wrapper command is unrelated to the scripts themselves).
  implication: The PowerShell script modifications are syntactically valid.

- timestamp: 2026-08-15
  source: human verification checkpoint response
  observation: After the client-cert chain fix, dlpctl loads the admin cert, key, and admin CA PEM successfully, builds a reqwest Identity, and rustls reaches "Attempting client auth" after receiving the server cert. Immediately afterward the connection is reset with `peer closed connection without sending TLS close_notify`. The server tls-events.log still shows `tls handshake eof`.
  implication: The client now presents the provisioning-admin cert (probably with the issuing CA), but the server aborts the handshake after receiving it. The failure has moved from client-certificate selection to server-side chain validation or post-handshake identity rejection.

- timestamp: 2026-08-15
  source: code inspection of dlp-server/src/tls.rs
  observation: The server builds a `WebPkiClientVerifier` from `DLP_ADMIN_CA_CERT_PEM` and `DLP_DEVICE_ISSUING_CA_CERT_PEM`, allows unauthenticated connections, and then maps the verified leaf to `PeerIdentity` via `IdentityRoots::peer_identity`. The identity check compares the leaf issuer string to the configured admin-ca/device-issuing-ca subjects.
  implication: A server-side abort immediately after receiving the client cert is most likely a webpki chain-validation failure inside `WebPkiClientVerifier`, not the later `IdentityRoots` string comparison.

- timestamp: 2026-08-15
  source: code change to dlp-server/src/tls.rs
  observation: Added a `LoggingClientCertVerifier` wrapper around the `WebPkiClientVerifier` that logs every call to `verify_client_cert`, including the presented chain subjects/issuers, the number of hinted authority subjects, and the exact `rustls::Error` if verification is rejected. The wrapper delegates all verification unchanged.
  implication: The next failed run will produce a server-side log entry showing exactly why webpki rejected (or accepted) the provisioning-admin chain.

- timestamp: 2026-08-15
  source: cargo check / cargo test -p dlp-server --lib
  observation: `cargo check -p dlp-server` and `cargo test -p dlp-server --lib` both pass (9 tests passed).
  implication: The server instrumentation compiles and existing unit tests still pass.

- timestamp: 2026-08-15
  source: code change to scripts/lab/Debug-TrustedProvisioningTls.ps1
  observation: Extended the openssl s_client helper to extract and report `acceptable_client_ca_names` and `verify_return_code` for both server-auth-only and mutual-TLS probes. This shows the authority_names the server advertises and whether openssl itself can complete the handshake.
  implication: The diagnostic snapshot will now confirm whether the server loads admin-ca as a client-auth trust anchor and whether an openssl-based mutual-TLS handshake fails with the same alert as dlpctl.

- timestamp: 2026-08-15
  source: PowerShell parser syntax check
  observation: `Debug-TrustedProvisioningTls.ps1` reports `SYNTAX OK` via `[System.Management.Automation.PSParser]::Tokenize`.
  implication: The diagnostic script changes are syntactically valid.

- timestamp: 2026-08-15
  source: code inspection of Invoke-Dc01Server.ps1
  observation: Install-Dc01ServerSecrets (lines 310-341) assigns $env:DLP_SERVER_CERT_PEM, $env:DLP_SERVER_KEY_PEM, $env:DLP_ADMIN_CA_CERT_PEM, $env:DLP_PHASE1_ROOT_CA_CERT_PEM, $env:DLP_DEVICE_ISSUING_CA_CERT_PEM, and $env:DLP_DEVICE_ISSUING_CA_KEY_PEM directly into the $secrets hashtable and writes them to C:\dlp\secrets\*.pem without resolving path values to file content.
  implication: When the environment variables contain paths (the Set-DlpEnvironment.ps1 defaults), the script writes the path string into the .pem file instead of the PEM content.

- timestamp: 2026-08-15
  source: code inspection of Invoke-TrustedProvisioning.ps1
  observation: The script writes $env:DLP_PROVISIONING_ROOT_CA_PEM, $env:DLP_PROVISIONING_ADMIN_CERT_PEM, and $env:DLP_PROVISIONING_ADMIN_KEY_PEM directly to C:\dlp\provisioning\*.pem (lines 128-131) without resolving path values.
  implication: Path-valued provisioning variables are also written as literal path strings, corrupting dlpctl's input files.

- timestamp: 2026-08-15
  source: code inspection of Invoke-Client01Runtime.ps1
  observation: Install-Client01ServerSecrets uses Get-Client01SecretValue, which returns inline PEM as-is and reads file-path values into their PEM content before writing to LAB-DC01. Assert-Client01ServerSecretsValid also resolves content before hashing.
  implication: Invoke-Client01Runtime.ps1 is not the source of the path-files on LAB-DC01; the corruption comes from Invoke-Dc01Server.ps1 or a direct run of Invoke-TrustedProvisioning.ps1 with path-valued env vars.

- timestamp: 2026-08-15
  source: code inspection of Set-DlpEnvironment.ps1
  observation: The default values for DLP_SERVER_CERT_PEM, DLP_SERVER_KEY_PEM, DLP_ADMIN_CA_CERT_PEM, DLP_PHASE1_ROOT_CA_CERT_PEM, DLP_DEVICE_ISSUING_CA_CERT_PEM, and DLP_DEVICE_ISSUING_CA_KEY_PEM are file paths such as C:\dlp\secrets\server-cert.pem.
  implication: Any script that writes these env vars directly to disk without resolving them will create path-files.

- timestamp: 2026-08-15
  source: server startup logic in dlp-server/src/tls.rs
  observation: TlsPaths::server_config reads each configured file once at startup via load_certificates/load_private_key and holds the parsed material in the ServerConfig. It does not reload from disk after startup.
  implication: A server that was started before the secrets files were overwritten with path strings can continue to serve TLS using the old certificates, explaining why verify_client_cert accepted despite C:\dlp\secrets\*.pem now containing paths.

- timestamp: 2026-08-15
  source: dlp-server/src/routes.rs admin_provisioning_contract and require_administrator
  observation: The protected route has no debug logging between the TLS identity check and the provisioning service call. A panic or early connection drop inside the handler would not be visible in tls-events.log.
  implication: The post-handshake reset requires HTTP-layer instrumentation to determine whether the request reaches the handler, fails validation, or fails inside the provisioning service/repository.

- timestamp: 2026-08-15
  source: code changes to Invoke-Dc01Server.ps1 and Invoke-TrustedProvisioning.ps1
  observation: Added Resolve-PemContent helper to both scripts. Install-Dc01ServerSecrets now resolves DLP_SERVER_CERT_PEM, DLP_SERVER_KEY_PEM, DLP_ADMIN_CA_CERT_PEM, DLP_PHASE1_ROOT_CA_CERT_PEM, DLP_DEVICE_ISSUING_CA_CERT_PEM, DLP_DEVICE_ISSUING_CA_KEY_PEM, and optional DLP_AD_CA_CERT_PEM from paths to PEM content before writing to C:\dlp\secrets\. Invoke-TrustedProvisioning.ps1 resolves DLP_PROVISIONING_ROOT_CA_PEM, DLP_PROVISIONING_ADMIN_CERT_PEM, and DLP_PROVISIONING_ADMIN_KEY_PEM before writing to C:\dlp\provisioning\.
  implication: Path-valued env vars will no longer be written as literal strings into .pem files.

- timestamp: 2026-08-15
  source: code change to Debug-TrustedProvisioningTls.ps1
  observation: Added looks_like_path flag for every inspected provisioning and secrets file, and fixed a pre-existing syntax error where try/catch statements were used directly as hashtable values.
  implication: Future diagnostic snapshots will clearly flag any file whose content is a path instead of PEM.

- timestamp: 2026-08-15
  source: code changes to dlp-server/src/tls.rs and dlp-server/src/routes.rs
  observation: Added AuthenticatedAdmin::subject() accessor and HTTP-layer logging in require_administrator and admin_provisioning_contract. The handler now logs whether an identity is present, the admin subject, request field lengths, and provisioning success/failure.
  implication: The next failed run will show whether the reset happens before the handler, during validation, or inside the provisioning service/repository.

- timestamp: 2026-08-15
  source: code change to crates/dlpctl/src/lib.rs
  observation: ProvisioningClient::provision now logs the target endpoint/device before sending and logs the HTTP status/body when the response is non-success.
  implication: dlpctl diagnostics will distinguish a transport reset from an HTTP error response.

- timestamp: 2026-08-15
  source: PowerShell parser syntax check after fixes
  observation: Invoke-Dc01Server.ps1, Invoke-TrustedProvisioning.ps1, and Debug-TrustedProvisioningTls.ps1 all report zero parse errors via [System.Management.Automation.PSParser]::Tokenize with a proper [ref]$err argument.
  implication: The modified PowerShell scripts are syntactically valid.

- timestamp: 2026-08-15
  source: cargo check / cargo test after Rust changes
  observation: cargo check -p dlp-server, cargo check -p dlpctl, cargo test -p dlp-server --lib (9 tests), and cargo test -p dlpctl --lib (5 tests) all pass.
  implication: The Rust logging changes compile and do not break existing unit tests.

- timestamp: 2026-08-15
  source: human verification checkpoint response (LAB-DC01 diagnostics)
  observation: |
    - All secrets/provisioning files now contain valid PEM content (no path-files).
    - dlp-server.err confirms TLS trust anchors loaded correctly: admin_ca=CN=admin-ca, O=DLP Lab, device_ca=CN=device-issuing-ca, O=DLP Lab, server_cert=CN=LAB-DC01.lab.local, O=DLP Lab.
    - `verify_client_cert called` and `verify_client_cert accepted` appear in the server log.
    - dlpctl.err shows the provisioning POST is sent to `https://LAB-DC01.lab.local:8443/api/v1/admin/provisioning`.
    - The connection still resets after the TLS handshake succeeds.
    - dlp-server.log is empty.
  implication: The TLS handshake and client-certificate verification are now healthy. The reset is post-handshake, after the client believes it can send the HTTP request. The server-side HTTP stack is the next place to look.

- timestamp: 2026-08-15
  source: dlp-server/Cargo.toml and axum 0.8.9 feature analysis
  observation: dlp-server depends on `axum = "=0.8.9"` with default features. Axum 0.8.9 defaults are `["form", "http1", "json", "matched-path", "original-uri", "query", "tokio", "tower-log", "tracing"]`; the `http2` feature is not enabled by default. dlpctl depends on `reqwest` with the `http2` feature.
  implication: The server advertises HTTP/2 via ALPN (`configuration.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()]`) but the compiled Axum/hyper-util stack only supports HTTP/1. A reqwest client that negotiates h2 will send an HTTP/2 preface that the server cannot serve, causing hyper-util to close the connection with `HTTP/2 is not supported`.

- timestamp: 2026-08-15
  source: hyper-util 0.1.20 server/conn/auto/mod.rs
  observation: `serve_connection_with_upgrades` first reads the first 24 bytes to detect the HTTP/2 preface. If the preface matches and the `http2` feature is not compiled in, it returns `Err("HTTP/2 is not supported")`. Axum traces this but sends no HTTP response, so the TLS connection is simply closed.
  implication: This behavior exactly matches a successful TLS handshake followed by a client-side "connection reset" with no HTTP response and no route-layer logs.

## Resolution

- root_cause: |
    dlp-server's axum dependency was compiled without the http2 feature, but the server's rustls configuration advertised h2 via ALPN. The reqwest-based dlpctl client (http2 enabled) negotiated HTTP/2, sent the HTTP/2 connection preface after the mTLS handshake, and the server closed the TLS connection because hyper-util could not serve HTTP/2 in that build configuration.
- fix: |
    Enabled the axum http2 feature in crates/dlp-server/Cargo.toml so the server's advertised ALPN protocol is actually supported. Added ALPN-protocol logging in RustlsListener::accept to confirm the negotiated protocol in future diagnostics.
- verification: |
    Self-verified: cargo check -p dlp-server, cargo test -p dlp-server --lib (9 passed), cargo check -p dlpctl, cargo test -p dlpctl --lib (5 passed). End-to-end verification pending on LAB-DC01.
- files_changed:
    - crates/dlp-server/Cargo.toml: enabled axum http2 feature
    - crates/dlp-server/src/tls.rs: added negotiated ALPN protocol logging
