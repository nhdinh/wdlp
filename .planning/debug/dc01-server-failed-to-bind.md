---
status: investigating
trigger: "Investigate debug session for Invoke-Dc01Server.ps1 Tracer scenario failure: Error: DatabaseUnavailable / server_failed_to_bind"
created: 2026-08-13T00:00:00Z
updated: 2026-08-13T00:00:00Z
---

## Current Focus

hypothesis: "The DATABASE_URL passed to dlp-server.exe on LAB-DC01 does not resolve to a reachable PostgreSQL listener from LAB-DC01. The PowerShell wrapper mislabels the resulting startup failure as server_failed_to_bind, but the underlying Rust error is ServerError::DatabaseUnavailable raised during eager database connection before the TCP listener is ever bound."
test: "Read Invoke-Dc01Server.ps1 and dlp-server startup sequence; verify error emission points and ordering."
expecting: "Confirm DatabaseUnavailable originates from PgPoolOptions::connect in run_server, not from listener bind, and that the script forwards DLP_DATABASE_URL unchanged to LAB-DC01."
next_action: "Update session file with confirmed root cause and configuration-level fix recommendation; no code edit required."

## Symptoms

expected: "Tracer scenario should start dlp-server.exe on LAB-DC01, the server should bind to 0.0.0.0:8443, and LAB-CLIENT01 should receive ok responses from /health/live and /health/ready."
actual: "After installing binary and secrets, dlp-server.exe emits Error: DatabaseUnavailable to stderr. The WaitForReady TCP probe to 127.0.0.1:8443 never succeeds, and Invoke-Dc01Server.ps1 throws server_failed_to_bind."
errors:
  - "Error: DatabaseUnavailable (from C:\\dlp\\server\\dlp-server.err)"
  - "server_failed_to_bind (PowerShell wrapper exception)"
reproduction: "Run .\\scripts\\lab\\Invoke-Dc01Server.ps1 -CallerMachine hungdinh-lt -ExecutionMachine LAB-DC01 -ProbeMachine LAB-CLIENT01 -SecretProvider Runtime -Scenario Tracer -Credential $cred"
started: "Observed during Tracer scenario execution on 2026-08-13."

## Eliminated

- hypothesis: "Another process on LAB-DC01 is already listening on TCP 8443, causing bind failure."
  evidence: "dlp-server emits ServerError::DatabaseUnavailable, not ServerError::ListenerFailed. Listener binding occurs only after a successful PostgreSQL connection and migration run (crates/dlp-server/src/lib.rs run_server lines 440-447). A port collision would produce ListenerFailed or a different stderr message, not DatabaseUnavailable."
  timestamp: 2026-08-13T00:00:00Z

## Evidence

- timestamp: 2026-08-13T00:00:00Z
  checked: "crates/dlp-server/src/lib.rs run_server and ProductionProviders::from_environment"
  found: "run_server eagerly connects to PostgreSQL with PgPoolOptions::new().connect(&config.database_url).await and maps any error to ServerError::DatabaseUnavailable (line 443). TCP listener binding happens only after this connect succeeds and migrations run (lines 444-447)."
  implication: "A DatabaseUnavailable error means the server never attempted to bind port 8443. The server_failed_to_bind wrapper message is misleading."

- timestamp: 2026-08-13T00:00:00Z
  checked: "scripts/lab/Invoke-Dc01Server.ps1 Start-Dc01Server and WaitForReady logic"
  found: "The script writes DATABASE_URL=$env:DLP_DATABASE_URL verbatim into C:\\dlp\\server\\server.env, loads it into the PowerShell Direct process environment, and starts dlp-server.exe. The WaitForReady loop probes 127.0.0.1:$ServerPort for up to 60 seconds; on timeout it prints dlp-server.err and throws server_failed_to_bind (lines 400-425)."
  implication: "The database URL is forwarded unchanged. If DLP_DATABASE_URL points to localhost, 127.0.0.1, or a host resolvable only on hungdinh-lt, migrations can succeed on the orchestrator while the server on LAB-DC01 cannot reach PostgreSQL."

- timestamp: 2026-08-13T00:00:00Z
  checked: "config/lab.phase1.example.yaml and .planning/docs/LAB-SERVER01-SETUP.md"
  found: "LAB-SERVER01 is the database server at 192.168.50.12. Documentation specifies DLP_DATABASE_URL should use postgres://dlp_server:***@192.168.50.12:5432/dlp and that pg_hba.conf should allow 192.168.50.0/24."
  implication: "The intended database endpoint for LAB-DC01 is 192.168.50.12:5432. Any URL that does not use this address from LAB-DC01's perspective will fail."

- timestamp: 2026-08-13T00:00:00Z
  checked: "Invoke-Dc01Server.ps1 migration execution"
  found: "Invoke-SqlxMigrate runs sqlx migrate run on the orchestrator host (hungdinh-lt) using $env:DLP_DATABASE_URL. It does not validate that LAB-DC01 can reach the same endpoint before starting the server."
  implication: "Successful migrations prove reachability from hungdinh-lt only; they do not prove reachability from LAB-DC01."

## Resolution

root_cause: "The DATABASE_URL environment variable supplied to dlp-server.exe on LAB-DC01 does not point to a PostgreSQL instance reachable from LAB-DC01. The most likely specific causes are (1) DLP_DATABASE_URL uses localhost/127.0.0.1 or a host-local name instead of 192.168.50.12 (LAB-SERVER01), or (2) network/firewall/pg_hba.conf on LAB-SERVER01 blocks inbound PostgreSQL connections from LAB-DC01 (192.168.50.10). The PowerShell wrapper's server_failed_to_bind exception is a secondary symptom of the server process exiting with ServerError::DatabaseUnavailable before binding."
fix: "Configuration/environment remediation only; no code change required. 1) Verify DLP_DATABASE_URL uses postgres://dlp_server:<password>@192.168.50.12:5432/dlp on the orchestrator host. 2) From LAB-DC01, confirm reachability with Test-NetConnection 192.168.50.12 -Port 5432. 3) On LAB-SERVER01, ensure postgresql.conf has listen_addresses = '192.168.50.12,localhost' and pg_hba.conf contains 'host dlp dlp_server 192.168.50.0/24 scram-sha-256' (or a rule covering 192.168.50.10/32). 4) Re-run the Tracer scenario."
verification: "Not yet performed in the live lab environment. Self-verified by code inspection only: the DatabaseUnavailable path precedes listener binding, and the script forwards the database URL unchanged."
files_changed: []
