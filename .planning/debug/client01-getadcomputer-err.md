---
status: awaiting_human_verify
trigger: Fix the script Invoke-Client01Runtime.ps1 because it return this error while LAB-DC01 is up and reachable. "Get-ADComputer: C:\Users\nhdinh\dev\dleakprevention\scripts\lab\Invoke-Client01Runtime.ps1:71
Line |
  71 |      Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Sc …
     |      ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
     | Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running."
created: 2026-08-14
updated: 2026-08-15T00:45:00Z
---

# Debug Session: client01-getadcomputer-err

## Symptoms

- **Expected behavior:** Script contacts LAB-DC01 and proceeds.
- **Actual behavior:** Get-ADComputer fails to contact server.
- **Error messages:** `Get-ADComputer: ... Unable to contact the server. This may be because this server does not exist, it is currently down, or it does not have the Active Directory Web Services running.`
- **Timeline:** Never worked.
- **Reproduction:** Only after specific steps — LAB-DC01 must be up and reachable before the error appears.

## Current Focus

- **hypothesis:** The provisioning admin certificate signature is now accepted by the server (no new BadSignature entries), but the TLS handshake still aborts because either (1) the admin CA lacks Basic Constraints CA:TRUE / Key Usage keyCertSign, or (2) the provisioning admin client certificate lacks Key Usage digitalSignature / Extended Key Usage clientAuth. rustls/webpki requires these extensions for client certificate validation. The failure mode is a fatal alert that the server logs as `tls handshake eof` and the client reports as `stream closed because of a broken pipe`.
- **test:** Run `Verify-DlpLabCertificates.ps1` to see the new extension checks. If the admin CA or provisioning admin cert fails the extension checks, regenerate the provisioning admin cert with `Rotate-DlpProvisioningAdmin.ps1 -Force` (which now adds v3_client extensions). If the admin CA itself fails, it must be regenerated with v3_ca extensions.
- **expecting:** `Verify-DlpLabCertificates.ps1` will either pass all checks (then re-run Tracer) or fail with a specific missing-extension code, telling us which certificate to regenerate.
- **next_action:** Ask the user to run `Verify-DlpLabCertificates.ps1` and report the result.

reasoning_checkpoint:
  hypothesis: "rustls/webpki rejects the provisioning admin certificate chain because required X.509 extensions are missing: the admin CA needs Basic Constraints CA:TRUE and Key Usage keyCertSign; the client cert needs Key Usage digitalSignature and Extended Key Usage clientAuth."
  confirming_evidence:
    - "After rotating the provisioning admin cert, tls-events.log no longer shows BadSignature for new connections; the cert signature is accepted."
    - "dlpctl now fails with 'stream closed because of a broken pipe' and the server logs 'tls handshake eof', consistent with a fatal alert during handshake extension validation."
    - "The original provisioning admin cert was generated with simple openssl req/x509 commands without specifying v3 extensions."
    - "The rotation script previously did not add digitalSignature or clientAuth extensions to the new cert."
  falsification_test: "If Verify-DlpLabCertificates.ps1 reports all extension checks pass and the Tracer run still fails with broken pipe, then the cause is not missing extensions; we would need to capture rustls debug logs or packet traces."
  fix_rationale: "Add explicit extension checks to Verify-DlpLabCertificates.ps1 so the user can see exactly which extension is missing. Update Rotate-DlpProvisioningAdmin.ps1 to generate a CSR and certificate with v3_client extensions (digitalSignature, clientAuth). If the admin CA lacks CA extensions, regenerate it with v3_ca extensions."
  blind_spots:
    - "We have not yet run the updated verification script, so we do not know whether the admin CA or the client cert is missing extensions."
    - "If the admin CA itself is missing Basic Constraints, we will need to regenerate it and then rotate the provisioning admin cert again."
  candidate_causes:
    - "data: admin CA certificate generated without Basic Constraints CA:TRUE / Key Usage keyCertSign."
    - "data: provisioning admin client certificate generated without Key Usage digitalSignature / EKU clientAuth."
    - "environment: rustls/webpki version enforces stricter extension validation than Windows X509Chain or OpenSSL verify."
  and_gate: "no"

## Evidence

- timestamp: 2026-08-14
  checked: ADWS readiness and LAB-DC01 reachability
  found: Active Directory Web Services is ready before trusted provisioning runs.
  implication: The original Get-ADComputer failure is resolved; the current blocker is downstream trusted provisioning.

- timestamp: 2026-08-14
  checked: dlpctl binary staging and Invoke-TrustedProvisioning.ps1 hash
  found: dlpctl.exe is rebuilt from source and staged to C:\dlp\provisioning\dlpctl.exe (length 9879040). Invoke-TrustedProvisioning.ps1 hash matches (e1c5dc1f...).
  implication: Stale-binary/stale-script hypotheses are eliminated for this run.

- timestamp: 2026-08-14
  checked: C:\dlp\provisioning\dlpctl.err, dlpctl.log and C:\dlp\server\dlp-server.log, dlp-server.err after failure
  found: All four log files are empty (length 0). The only error text visible is the top-level reqwest message propagated by the thrown exception.
  implication: The native executable's stderr/stdout is not being captured by the PowerShell `& ... 2>... >...` redirection inside the remote session.

- timestamp: 2026-08-14
  checked: C:\dlp\server\startup-diagnostic.log
  found: Environment variables are written correctly, including DLP_LISTEN_ADDRESS=0.0.0.0:8443 and all PEM paths pointing to C:\dlp\secrets.
  implication: Server startup code ran at some point and had the expected environment, but we cannot tell from logs whether a healthy server process is currently running.

- timestamp: 2026-08-15
  checked: latest Verify-DlpLabCertificates.ps1 output after switching to openssl modulus comparison
  found: All certificate/key checks passed, including server, device CA, and provisioning admin modulus matches. The PowerShell null-valued-expression issue was resolved by using openssl instead of .NET RSA Span APIs.
  implication: The orchestrator-side PEM files are internally consistent; the TLS BadSignature is not caused by a mismatch between DLP_SERVER_CERT_PEM and DLP_SERVER_KEY_PEM on the orchestrator.

- timestamp: 2026-08-15
  checked: rustls BadSignature semantics and possible causes
  found: rustls reports BadSignature when the client rejects the server certificate's signature itself, not the issuer. Common causes are a corrupted/stale cert file on the client/host, an unsupported signature algorithm (MD5/SHA-1), or an RSA key smaller than 2048 bits.
  implication: Need to verify the files actually installed on LAB-DC01 and check rustls compatibility of the certificate.

- timestamp: 2026-08-15
  checked: Invoke-Client01Runtime.ps1 and Verify-DlpLabCertificates.ps1 enhancements
  found: Added Assert-Client01ServerSecretsValid to verify installed server cert/key modulus, RSA key size, signature algorithm, and chain on LAB-DC01. Added signature-algorithm and key-size prints/checks to Verify-DlpLabCertificates.ps1.
  implication: Next run will fail fast if the installed secrets are corrupt or rustls-incompatible, and will print the exact signature algorithm and key size for diagnosis.

- timestamp: 2026-08-15
  checked: latest Tracer run output
  found: Server was already running with hash_matches=true, but tls-events.log still shows invalid peer certificate: BadSignature from the orchestrator IP. dlpctl receives received fatal alert: DecryptError. The new Assert-Client01ServerSecretsValid inside Start-Client01Server never ran because the server was considered ready.
  implication: The running server is using secrets installed on LAB-DC01 that do not match the orchestrator's current resolved secrets. The orchestrator's local verification passes because it checks the current env, not the VM's files.

- timestamp: 2026-08-15
  checked: latest Tracer run with secret-hash comparison
  found: secret_hash_matches=true for server-cert.pem, server-key.pem, and phase1-root-ca.pem, but tls-events.log still shows invalid peer certificate: BadSignature from 192.168.50.10 (orchestrator IP). dlpctl receives received fatal alert: DecryptError.
  implication: The installed server cert/key/root-ca files match the orchestrator. The error is now clearly rustls on the server rejecting the client's provisioning-admin certificate, not the client rejecting the server certificate.

- timestamp: 2026-08-15
  checked: dlp-server TLS configuration and client-certificate verifier
  found: The server builds a WebPkiClientVerifier from DLP_ADMIN_CA_CERT_PEM and DLP_DEVICE_ISSUING_CA_CERT_PEM. The BadSignature error from rustls means the provisioning admin cert's signature cannot be validated against the admin CA trust anchor. Possible causes: (1) provisioning-admin-cert.pem is not actually signed by admin-ca.pem, (2) admin-ca.pem is rejected by rustls (SHA-1/MD5 signature or <2048-bit key), (3) the server loaded the wrong admin-ca.pem file.
  implication: Need to verify the actual signature of DLP_PROVISIONING_ADMIN_CERT_PEM against DLP_ADMIN_CA_CERT_PEM and confirm the server loads the expected CA subject.

- timestamp: 2026-08-15
  checked: Invoke-Client01Runtime.ps1 secret-hash check expansion and Verify-DlpLabCertificates.ps1 signature verification
  found: Extended Assert-Client01ServerReady to compare hashes of admin-ca.pem and device-issuing-ca.pem as well. Rewrote Verify-DlpLabCertificates.ps1 to perform real X509Chain signature verification for both server cert against provisioning root and provisioning admin cert against admin CA, and to check admin CA signature algorithm for rustls compatibility.
  implication: Next verification run will fail fast if the provisioning admin cert is not actually signed by the admin CA or if the admin CA uses an unsupported algorithm. Next Tracer run will reinstall secrets if admin-ca.pem/device-issuing-ca.pem differ.

- timestamp: 2026-08-15
  checked: Verify-DlpLabCertificates.ps1 with real signature verification
  found: "FAIL: signature_verification_failed:provisioning admin cert - The signature of the certificate cannot be verified. A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider." All other checks passed (server cert signed by phase1-root-ca, modulus matches, RSA key sizes, sha256RSA signatures).
  implication: The provisioning admin certificate's issuer name is O=DLP Lab, CN=admin-ca, but it was NOT actually signed by the current DLP_ADMIN_CA_CERT_PEM. This is the root cause of the rustls BadSignature/DecryptError. The server cannot validate the client cert against its admin CA trust anchor.

- timestamp: 2026-08-15
  checked: Tracer run after dlp-server rebuild and secret reinstallation
  found: Server binary was rebuilt and secrets were reinstalled (all hashes match). New tls-events.log entries still show invalid peer certificate: BadSignature. dlpctl still gets received fatal alert: DecryptError.
  implication: The freshly installed provisioning admin cert/key are still the ones that do not chain to the current admin CA, confirming the certificate files themselves are the problem.

- timestamp: 2026-08-15
  checked: pki directory structure and certificate-generation scripts
  found: The provisioning admin cert was likely generated without the v3 extensions rustls/webpki requires (keyUsage digitalSignature, extendedKeyUsage clientAuth), and the admin CA may also lack Basic Constraints CA:TRUE / Key Usage keyCertSign if generated with a plain openssl req -x509 command.
  implication: Even after fixing the signature mismatch, rustls/webpki may still reject the client certificate chain for missing X.509 extensions, causing a handshake abort that appears as 'broken pipe' or 'tls handshake eof' rather than a clear BadSignature message.

- timestamp: 2026-08-15
  checked: Tracer run after rotating provisioning admin cert with fixed rotation script
  found: Server restarted with new binary. tls-events.log no longer shows new BadSignature entries for provisioning attempts. The server startup log shows the correct admin_ca subject. dlpctl error changed from 'received fatal alert: DecryptError' to 'stream closed because of a broken pipe'. Latest tls-events.log entries are 'tls handshake eof' from 127.0.0.1 and 192.168.50.10.
  implication: The provisioning admin certificate signature is now accepted (no BadSignature), but the TLS handshake still does not complete. This is consistent with rustls/webpki rejecting the admin CA or the client certificate for missing required extensions (Basic Constraints CA:TRUE/keyCertSign for the CA, digitalSignature/clientAuth EKU for the client cert), which causes a fatal alert and connection reset.

- timestamp: 2026-08-15
  checked: Verify-DlpLabCertificates.ps1 and Rotate-DlpProvisioningAdmin.ps1 extension checks
  found: Added OpenSSL-based checks for CA Basic Constraints CA:TRUE, Key Usage keyCertSign, client cert digitalSignature, and Extended Key Usage clientAuth. Updated rotation script to generate a CSR and cert with the required v3_client extensions.
  implication: Next verification run will fail fast if the admin CA or provisioning admin cert lacks the extensions rustls/webpki requires. The rotation script will now generate a compliant client cert if re-run.
- timestamp: 2026-08-14
  checked: latest verification script output and orchestrator behavior
  found: Verify-DlpLabCertificates.ps1 reports rsa_create_failed:server, meaning DLP_SERVER_KEY_PEM cannot be parsed as an RSA private key. After restarting the stale server binary, tls-events.log shows invalid peer certificate: BadSignature. Assert-Client01ServerSecretsPresent now validates the server key header.
  implication: The server private key file is the wrong format, encrypted, or does not match the certificate. This is the current root cause blocking trusted provisioning.

- timestamp: 2026-08-14
  checked: dlp-server stderr capture and RustlsListener diagnostics
  found: dlp-server.err is empty even though the server must be receiving the connection. Added explicit tls-events.log file logging in RustlsListener::accept for accept failures, identity rejections, and no-client-cert connections.
  implication: Next run will reveal the exact server-side reason for the connection abort without relying on stderr capture.

- timestamp: 2026-08-14
  checked: cargo build --release -p dlpctl -p dlp-server and cargo test --test server_enrollment
  found: Build succeeded with one pre-existing dead_code warning. server_enrollment tests pass (20 passed) after updating the source-level assertion for the new Start-Process invocation.
  implication: Rust changes compile and existing e2e contracts still hold.

## Eliminated

## Resolution

- **root_cause:** The provisioning admin certificate (`DLP_PROVISIONING_ADMIN_CERT_PEM`) had issuer name `O=DLP Lab, CN=admin-ca` but its signature could not be verified by the current `DLP_ADMIN_CA_CERT_PEM`. After rotation, the signature is accepted but the TLS handshake still aborts, likely because the admin CA or the client certificate lacks the X.509 extensions rustls/webpki requires (Basic Constraints CA:TRUE/keyCertSign on the CA; digitalSignature/clientAuth EKU on the client cert).
- **fix:**
  1. Regenerate the provisioning admin certificate using the current admin CA with `scripts/lab/Rotate-DlpProvisioningAdmin.ps1` (now adds v3_client extensions).
  2. If `Verify-DlpLabCertificates.ps1` reports the admin CA itself lacks CA extensions, regenerate the admin CA with `openssl req -x509 ... -extensions v3_ca` and then rotate the provisioning admin cert again.
- **verification:**
  - `Verify-DlpLabCertificates.ps1` now checks certificate signatures and required X.509 extensions.
  - After running `Rotate-DlpProvisioningAdmin.ps1` and fixing any CA extension issues, `Verify-DlpLabCertificates.ps1` should pass, and the Tracer scenario should complete trusted provisioning successfully.
- **files_changed:** scripts/lab/Invoke-TrustedProvisioning.ps1, scripts/lab/Invoke-Client01Runtime.ps1, scripts/lab/Verify-DlpLabCertificates.ps1, scripts/lab/Rotate-DlpProvisioningAdmin.ps1, crates/dlpctl/src/lib.rs, crates/dlp-server/src/tls.rs, tests/e2e/server_enrollment.rs
