---
status: awaiting_human_verify
trigger: "Running .\\scripts\\lab\\Invoke-Client01Runtime.ps1 returned error: Start-Service failed on Invoke-Client01Runtime.ps1:69; Windows could not start the DLP Windows Endpoint Service service on Local Computer. Error 1: Incorrect function."
created: 2026-08-13T00:00:00Z
updated: 2026-08-13T00:00:00Z
---

## Current Focus

hypothesis: "The service binary starts and enters service_main, but exits early through one of the Stopped-with-exit-code-1 paths. The SCM surfaces the service-reported Win32 exit code 1 as 'Error 1: Incorrect function'. The most likely underlying causes are a missing enrollment token or rustls using the aws-lc-rs crypto provider in a Windows service context, which the project guidelines explicitly avoid."
test: "Re-run Invoke-Client01Runtime.ps1 with -Apply after the fix and inspect C:\\dlp\\agent\\logs\\dlp-windows-service.log."
expecting: "Start-Service succeeds, or the log reveals the exact remaining failure (e.g., network enrollment failure) instead of the opaque 'Error 1' message."
next_action: "User is obtaining DLP_AGENT_ENROLLMENT_TOKEN via dlpctl provision-device from the trusted provisioning station; then re-run the script."

## Symptoms

expected: "The DLP Windows Endpoint Service should start successfully inside the VM and the runtime script should proceed."
actual: "PowerShell reports Start-Service failed on Invoke-Client01Runtime.ps1:69 and Windows shows 'Error 1: Incorrect function.'"
errors:
  - "Start-Service: ... Failed to start service 'DLP Windows Endpoint Service (DlpWindowsService)'."
  - "Windows could not start the DLP Windows Endpoint Service service on Local Computer. Error 1: Incorrect function."
reproduction: "Run .\\scripts\\lab\\Invoke-Client01Runtime.ps1 against the lab client VM."
started: "Observed during lab client runtime execution on 2026-08-13."

## Eliminated

- hypothesis: "The service binary is not a valid Windows executable or has wrong subsystem/architecture."
  evidence: "file(1) reports 'PE32+ executable for MS Windows 6.00 (console), x86-64'. ldd shows only system DLLs and no VC++ runtime dependency (crt-static is working). The binary also runs from a console and prints the expected dispatcher-failure message."
  timestamp: 2026-08-13T00:00:00Z

- hypothesis: "The Tokio runtime cannot be created because required features are missing."
  evidence: "dlp-windows-service enables rt-multi-thread/time/macros/sync. reqwest (blocking/rustls/http2) transitively enables tokio net/time. cargo test -p dlp-windows-service --release passes, including runtime-using paths."
  timestamp: 2026-08-13T00:00:00Z

- hypothesis: "The service name or SCM entrypoint registration is mismatched."
  evidence: "Script and code both use 'DlpWindowsService'. define_windows_service! and service_dispatcher::start follow the windows-service crate pattern."
  timestamp: 2026-08-13T00:00:00Z

## Evidence

- timestamp: 2026-08-13T00:00:00Z
  checked: "Invoke-Client01Runtime.ps1 service install path"
  found: "Script uses New-Service -Name DlpWindowsService -BinaryPathName 'C:\\dlp\\agent\\dlp-windows-service.exe' and Start-Service -Name DlpWindowsService. Environment variables are persisted via HKLM\\SYSTEM\\CurrentControlSet\\Services\\DlpWindowsService\\Environment."
  implication: "The SCM is invoked with the expected service name; install plumbing is not obviously wrong."

- timestamp: 2026-08-13T00:00:00Z
  checked: "crates/dlp-windows-service/src/main.rs and service.rs"
  found: "main.rs calls dlp_windows_service::service::run_scm_service() which invokes service_dispatcher::start(\"DlpWindowsService\", ffi_service_main). service_main registers handler, sets StartPending, creates Tokio runtime, loads config, runs ServiceContext::startup, sets Running, then spawns run_service_loop and blocks."
  implication: "The entrypoint name matches the service name. Early errors in config/runtime/startup cause an immediate Stopped status, which can be misreported by Start-Service as error 1."

- timestamp: 2026-08-13T00:00:00Z
  checked: "crates/dlp-windows-service/Cargo.toml"
  found: "No [[bin]] subsection, no crate-type override, no build.rs. Tokio features are rt-multi-thread, time, macros, sync (no fs/net)."
  implication: "Default console binary should be produced. Missing build.rs is normal for windows-service crate, but fs/net features may matter if agent-core uses them."

- timestamp: 2026-08-13T00:00:00Z
  checked: "Binary type and dependencies"
  found: "target/release/dlp-windows-service.exe is PE32+ console x86-64. ldd shows only system DLLs (KERNEL32, KERNELBASE, crypt32, advapi32, sechost, ws2_32, etc.) with no vcruntime/msvcp dependency."
  implication: "The release binary is self-contained and the correct Windows service executable type."

- timestamp: 2026-08-13T00:00:00Z
  checked: "Console execution of the service binary"
  found: "Running target/release/dlp-windows-service.exe from bash prints 'service_dispatcher_failed: IO error in winapi call' and exits cleanly."
  implication: "The binary can start and reach the dispatcher call; it does not crash on load. The failure is specific to the SCM service path or the service's own early-return logic."

- timestamp: 2026-08-13T00:00:00Z
  checked: "ServiceContext::startup and load_service_config error paths"
  found: "service_main has three early returns that set Stopped with ServiceExitCode::Win32(1): Runtime::new failure, load_service_config failure, and ServiceContext::startup failure. ServiceContext::startup fails if credential store, cache, or enrollment fails."
  implication: "The Win32 exit code 1 maps to the Windows message 'Incorrect function', matching the observed Start-Service error. The actual cause is hidden because the service logs nothing before exiting."

- timestamp: 2026-08-13T00:00:00Z
  checked: "reqwest rustls crypto provider selection"
  found: "dlp-agent-core uses reqwest features [\"rustls\",\"blocking\",\"http2\"]. reqwest 0.13.4's rustls feature hardcodes __rustls-aws-lc-rs. The project CLAUDE.md explicitly recommends rustls::crypto::ring::default_provider() for a pure-Rust Windows build."
  implication: "The service uses aws-lc-rs despite project guidelines recommending ring. This is a plausible runtime failure vector inside a session-0 LocalSystem service process."

## Resolution

root_cause: "The service exits early through a Stopped-with-Win32-exit-code-1 path (most likely ServiceContext::startup failure caused by missing enrollment token or rustls/aws-lc-rs runtime failure in the service context), and the SCM reports exit code 1 as the generic 'Error 1: Incorrect function' message."
fix: |
  1. Added file logging to dlp-windows-service (C:\dlp\agent\logs\dlp-windows-service.log) so the exact early-return path is visible.
  2. Added DLP_AGENT_ENROLLMENT_TOKEN to Assert-RuntimeSecretsPresent so the script fails fast with a clear message when the token required for first-start enrollment is missing.
  3. Installed rustls::crypto::ring::default_provider() as the default TLS crypto provider in main.rs, aligning with project guidelines and avoiding aws-lc-rs in the service process.
verification: |
  - cargo test -p dlp-windows-service --release passes.
  - Running the binary from console creates the expected log entries and still reports the expected dispatcher failure.
  - PowerShell AST parse of the updated script succeeds.
files_changed:
  - crates/dlp-windows-service/src/service.rs
  - crates/dlp-windows-service/src/main.rs
  - crates/dlp-windows-service/Cargo.toml
  - scripts/lab/Invoke-Client01Runtime.ps1
