# Research: Pitfalls — Windows DLP Solution

## Domain
A user-mode Windows Data Leakage Prevention product that exposes a per-user encrypted virtual drive via WinFsp, enforces centrally signed policies at the drive boundary, queues audit events locally, and continues enforcement while offline.

## Critical Pitfalls

### 1. Treating WinFsp as a generic block device instead of an NTFS-like file system
- **Risk**: Explorer, Office, and antivirus expect exact NTFS semantics around reparse points, alternate data streams, case sensitivity, short names, `DeviceIoControl`, and oplocks. Missing or wrong implementations cause Explorer hangs, Office save failures, AV conflicts, and data corruption.
- **Warning signs**: Word/Excel fails to save with "disk full" or "access denied"; Explorer pauses for seconds when opening the drive; third-party apps crash on the protected drive while working fine on local disks.
- **Prevention**: Use `ntptfs-winfsp-rs` test suite as a conformance target, implement `GetVolumeInfo` with realistic `TotalSize`/`FreeSize`, handle `Cleanup`/`Close` reference counts correctly, and test against real Office workflows before writing policy logic. Audit every stubbed FSP operation.
- **Address in phase**: WinFsp drive spike and vertical-slice validation phase.

### 2. IRP cancellation and shutdown deadlocks in WinFsp
- **Risk**: A user-mode file system that holds a file-node lock while notifying the kernel of changes can deadlock during process termination because the in-flight IRP cannot be cancelled and `FspVolumeDelete` waits on a resource already held. The drive becomes unmountable and Explorer hangs.
- **Warning signs**: Dismount hangs; service process does not exit cleanly; Event Viewer shows `Application Hang` for the agent; volume is still listed after service stop.
- **Prevention**: Keep lock scopes small; never call `FspFileSystemNotify` while holding a file-node lock that a worker thread may need; implement explicit `FspFileSystemStopDispatcher` handling; use a watchdog timer during shutdown; and test unclean termination under load.
- **Address in phase**: WinFsp drive robustness phase (concurrent access / crash recovery).

### 3. Session and UAC isolation making the drive invisible
- **Risk**: A drive letter mounted from a Windows service (Session 0 or elevated token) is not visible in a standard user Explorer session. Users cannot find the protected drive even though the service reports success.
- **Warning signs**: Drive shows in `cmd.exe` run as Administrator but not in normal Explorer; user reports "drive did not appear"; automated tests run under different tokens from real users.
- **Prevention**: Mount the WinFsp volume from a process running in the target user's session with a linked token, or mount to a directory junction inside the user's profile instead of a drive letter. Validate visibility from a non-elevated interactive session on a clean Windows install.
- **Address in phase**: Per-user agent / companion process phase.

### 4. Blocking the async runtime or wrong mutex types in the Windows service
- **Risk**: A Windows service built with `tokio` that performs synchronous WinFsp I/O, file encryption, or policy evaluation inside async tasks can deadlock the runtime or make the service unresponsive to SCM stop requests.
- **Warning signs**: Service stop hangs for 30 seconds then reports "did not respond"; CPU is idle but pending I/O queue grows; Explorer operations on the drive time out.
- **Prevention**: Move synchronous work to `tokio::task::spawn_blocking`; use `tokio::sync::Mutex` across await points; keep service control handler non-blocking; and integrate `tokio::select!` with the SCM stop event. Profile service shutdown under load.
- **Address in phase**: Agent service skeleton + SCM integration phase.

### 5. Storing encryption keys alongside the encrypted backing store
- **Risk**: If the key, key-encryption key, or unwrapped key material is stored in the same directory or registry path as the ciphertext, an attacker with disk access can decrypt everything. This turns authenticated encryption into security theater.
- **Warning signs**: Key file found next to `.vault` or `.enc` files; registry contains base64 key material; backup of the store is self-decrypting; code uses a hardcoded key or derives the key solely from the SID.
- **Prevention**: Bind the store key to the Windows user identity via `CryptProtectData` / DPAPI-NG or a TPM-backed key; keep an offline recovery key only on the server in a separate key-encryption hierarchy; never write plaintext key material to logs or config files; and rotate keys on re-enrollment.
- **Address in phase**: Encrypted backing store / crypto foundation phase.

### 6. Clock-tampering and ambiguity in offline policy enforcement
- **Risk**: Relying on the endpoint clock to decide whether the cached signed policy is still within the seven-day offline window lets users backdate the clock and extend enforcement indefinitely, or advance it and lock themselves out early.
- **Warning signs**: Offline enforcement continues past the expiry date; lockout occurs immediately after a BIOS reset; logs show policy timestamps that disagree with event timestamps; users report being locked out after traveling.
- **Prevention**: Include server-issued `not-before`/`not-after` timestamps inside the signed policy bundle and reject activation of bundles whose `not-after` is already past. Use monotonic time for the local countdown, but validate against bundle expiry. Do not trust the system clock alone; consider a tamper-evident "last seen online" counter signed by the server.
- **Address in phase**: Signed policy bundle + offline enforcement phase.

### 7. Policy false positives that drive users to bypass the agent
- **Risk**: Overly broad content detectors or file-path rules block legitimate daily work. Users respond by saving files outside the protected drive, using personal cloud storage, or disabling the service, increasing leakage rather than reducing it.
- **Warning signs**: High volume of unblock/override requests; helpdesk tickets spike after rollout; sensitive files appear in `%TEMP%`, Downloads, or personal OneDrive; policy exception list grows faster than the rule set.
- **Prevention**: Start detectors with high-confidence thresholds and audit-only mode; require bounded context (e.g., regex + proximity + file type) before blocking; provide an explicit allow-list for approved destinations; and measure false-positive rate before enabling block actions.
- **Address in phase**: Policy engine + content detector phase and pilot deployment.

### 8. Session 0 service cannot show toast notifications
- **Risk**: The Windows service tries to call `ToastNotificationManager` directly and silently fails, so users receive no feedback when an operation is blocked. They blame Explorer, Office, or the file system.
- **Warning signs**: Service logs show notification sent but nothing appears; notifications work when running from a console but not as a service; user says "files just disappear" when copied.
- **Prevention**: Run a small per-user companion process in the interactive session and send notification requests over a named pipe from the service. The companion owns `AppNotificationManager` and must run non-elevated. Register a known AUMID and handle toast activation for single-instance behavior.
- **Address in phase**: Toast notification / companion process phase.

### 9. Unbounded content parsing crashes or hangs the agent
- **Risk**: Scanning every file type with regex or format-specific parsers on every read/write can hang on malformed files, zip bombs, memory-mapped Office documents, or very large files, causing the drive to stall.
- **Warning signs**: Agent CPU spikes on specific files; large copy operations hang indefinitely; service restarts after hitting watchdog timeout; crash dumps point to parser code.
- **Prevention**: Cap file size for scanning, limit total scan time with a cancellable timeout, whitelist known-safe extensions, run parsers in a sandboxed worker process, and refuse to inspect arbitrary encrypted archives as already declared out of scope.
- **Address in phase**: Policy engine + content detector phase.

### 10. Audit event queue loss when offline
- **Risk**: Enforcement events are stored only in memory or an unprotected local SQLite database. A crash or uninstall wipes the audit trail, and a malicious user can delete or modify events before upload.
- **Warning signs**: Event counts on the endpoint do not match server counts after reconnect; audit database is a plain file with no integrity check; events have no sequence numbers or cryptographic chaining; uninstall removes the audit store.
- **Prevention**: Append events to a hash-chained local log signed with a per-device key; keep the head signature in the server bundle so tampering is detectable on next sync; upload opportunistically with acknowledged sequence numbers; and protect the store from deletion using ACLs or a separate service-owned directory.
- **Address in phase**: Audit logging + local queue + server sync phase.

### 11. AV/EDR and backup agents conflicting with the virtual drive
- **Risk**: Antivirus, EDR, and backup software perform real-time scanning or snapshotting on the protected drive. Because WinFsp is user-mode, aggressive scanners can cause recursive I/O, deadlocks, or performance collapse.
- **Warning signs**: File operations are slow even for small files; Explorer takes seconds to enumerate; AV logs show repeated scans of the protected drive; backup jobs fail with "access denied" or "device not ready".
- **Prevention**: Document recommended exclusions for the backing-store directory and the mount point; expose a `Fsctl` or `DeviceIoControl` path that lets cooperating scanners query cleanliness; and test alongside at least one major enterprise AV/EDR suite during the pilot.
- **Address in phase**: Pilot deployment / operations readiness phase.

### 12. Unclean policy activation without rollback
- **Risk**: A new signed policy bundle is partially applied and then fails validation or crashes the service. The endpoint is left with a half-applied policy, or reverts to an empty default that blocks all access.
- **Warning signs**: Agent crashes shortly after policy sync; rules from old and new policy mix in enforcement logs; service cannot start after a policy update; offline devices show inconsistent behavior.
- **Prevention**: Apply policy atomically: validate the bundle signature and schema before replacing the active policy; write the new policy to a staging file and swap with a rename; keep the previous bundle as `policy.prev`; and on startup, load the most recent valid bundle or fall back to `policy.prev` rather than failing.
- **Address in phase**: Signed policy bundle + offline enforcement phase.

### 13. User identity changes break store binding
- **Risk**: The encrypted backing store is tied to a Windows SID or profile path. When a user is renamed, moved to a new domain, or uses a roaming profile, the agent can no longer unwrap the store key and the drive becomes unreadable.
- **Warning signs**: Re-enrollment creates a new empty drive; user cannot access files after a domain migration; two devices show different contents for the same user.
- **Prevention**: Bind the store key to a stable server-side user identifier, not the local SID; support re-keying during enrollment when the server confirms identity; store metadata about the last known SID only as a cache, not as the root of trust.
- **Address in phase**: Enrollment + identity binding phase.

### 14. Kernel caching breaks mandatory-locking semantics
- **Risk**: Enabling kernel caching while implementing user-mode file locking causes Windows to satisfy reads from cache without checking the user-mode lock, violating mandatory locking and allowing reads inside an exclusive lock.
- **Warning signs**: Multi-process access shows stale data; a writer holds an exclusive lock but readers still see old content; concurrency tests fail non-deterministically.
- **Prevention**: If you implement `Lock`/`Unlock`, disable kernel caching for streams that participate in locking, or ensure lock state is propagated to the kernel correctly. Prefer file-system-level advisory locking where possible and document the limitation.
- **Address in phase**: WinFsp drive concurrency / Office compatibility phase.

## Moderate Pitfalls

### 15. Large-file copy failures due to buffer or timeout limits
- **Risk**: Copying multi-gigabyte files through the virtual drive times out because the agent buffers too much in memory or the policy scanner cannot keep up.
- **Warning signs**: Large file copies abort at a consistent percentage; memory usage grows linearly with file size; network uploads through the drive are slower than direct disk copies.
- **Prevention**: Stream reads and writes without buffering the entire file; chunk large files for scanning; and expose realistic `VolumeInfo` sizes so callers do not assume unlimited space.
- **Address in phase**: WinFsp drive I/O performance phase.

### 16. Mounting as a disk instead of a network provider
- **Risk**: Choosing a disk-mode mount on 32-bit Windows or specific builds can fail with `STATUS_NOT_IMPLEMENTED`, and disk-mode mounts require more NTFS semantics than network-mode mounts.
- **Warning signs**: Mount fails on some Windows versions but works on others; `FspFsctlCreateVolume` returns `0xC0000002`; mount succeeds but Explorer treats the drive as removable.
- **Prevention**: Prefer network redirector mode unless there is a specific reason for disk mode; test the chosen mode on all target Windows 10/11 builds and on 32-bit if still supported.
- **Address in phase**: WinFsp drive spike phase.

### 17. Missing recovery path after seven-day lockout
- **Risk**: After the offline window expires, the drive locks and there is no documented way for an administrator to issue a signed recovery authorization without re-enrolling the device, causing downtime.
- **Warning signs**: Locked devices remain locked for days; support creates manual workarounds; recovery requires uninstall and re-install.
- **Prevention**: Design the recovery flow at the same time as the lockout rule: a signed recovery token from the server should extend offline time or unlock the drive once network access is restored.
- **Address in phase**: Offline enforcement + operations phase.

## Sources

- WinFsp deadlock on volume shutdown with in-flight read and NotifyWorkItem: https://github.com/winfsp/winfsp/issues/682
- WinFsp user-mode locking and kernel caching conflict: https://github.com/winfsp/winfsp/issues/116
- WinFsp mount point not showing in Windows Explorer: https://github.com/winfsp/winfsp/issues/416
- WinFsp disk file system creation failure on 32-bit Windows: https://github.com/winfsp/winfsp/issues/88
- WinFsp FUSE write access denied due to security descriptor mapping: https://github.com/winfsp/winfsp/issues/40
- WinFsp Rust bindings (winfsp-rs): https://github.com/SnowflakePowered/winfsp-rs
- Writing a Windows Service in Rust — dual mode and Event Log: https://davidhamann.de/2026/02/28/writing-a-windows-service-in-rust/
- Common async Rust pitfalls relevant to Windows services: https://reintech.io/blog/avoid-common-async-rust-pitfalls-deadlocks
- Common mistakes in Microsoft Purview DLP deployment: https://www.welkasworld.com/post/common-mistakes-you-may-be-making-with-data-loss-prevention
- Endpoint DLP deployment practitioner's guide: https://dlptest.com/endpoint-dlp-deployment-guide/
- Hidden costs of false positives in DLP: https://www.cyberhaven.com/blog/5-reasons-you-cant-afford-to-ignore-false-positives
- Tuning DLP to reduce false positives: https://www.cybersierra.co/blog/tune-dlp-false-positives
- Microsoft Endpoint DLP stopped working — timeout/fallback behavior: https://learn.microsoft.com/en-us/answers/questions/5879867/endpoint-dlp-stopped-working
- Palo Alto Endpoint DLP troubleshooting — policy push failures: https://docs.paloaltonetworks.com/enterprise-dlp/administration/configure-enterprise-dlp/endpoint-dlp/troubleshoot-endpoint-dlp
- Broadcom DLP agents offline / not checking in: https://knowledge.broadcom.com/external/article/174800/dlp-agents-havent-checked-in-or-are-offl.html
- Broadcom DLP 16.x endpoint agent certificate mismatch: https://knowledge.broadcom.com/external/article/389391/dlp-16x-endpoint-agent-fails-to-connect.html
- ManageEngine DLP policy conflict (audit vs block): https://pitstop.manageengine.com/portal/en/community/topic/dlp-policy-conflict
- Encrypted file storage best practices (key separation): https://phalanx.io/encrypted-file-storage-best-practices/
- Encryption key management enterprise storage: https://www.solved.scality.com/encryption-key-management/
- nginx-ui backup encryption key disclosure (CVE-2026-27944): https://github.com/advisories/GHSA-g9w5-qffc-6762
- Azure data security and encryption best practices: https://learn.microsoft.com/en-us/azure/security/fundamentals/data-encryption-best-practices
- Practical guide to tray icons and toast notifications — Session 0 IPC pattern: https://comcomponent.com/en/blog/windows-tray-icon-toast-notification-guide
- Flowtriq tamper-evident audit log hash chain: https://flowtriq.com/features/audit
- Wikantik tamper-evident audit log row hashing: https://www.wikantik.com/enterprise/audit-log.html
- OpenClaw immutable audit log chain: https://zedly.ai/blog/openclaw-immutable-audit-log
- Common DLP implementation failures: https://www.kickidler.com/info/common-dlp-implementation-failures-and-how-to-avoid-them
- Broadcom DLP known issues (server rollback failure): https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/26-1/new-and-changed/release-notes/dlp-known-issues.html
