---
status: complete
---

# Summary: Interactive DLP environment setup script

## Completed
- Created `scripts/lab/Initialize-DlpEnvironment.ps1`:
  - Catalogs all 52 `DLP_*` variables used by the Phase 1 lab.
  - Loads an optional `-EnvFile` before prompting.
  - Prompts only for variables that are missing, empty, or still contain `REPLACE_*` placeholders.
  - Securely masks passwords/seeds with `Read-Host -AsSecureString`.
  - Validates file paths, hex lengths, URLs, drive letters, and numeric values (bypass with `-SkipValidation`).
  - Supports `-OutEnvFile` to persist the resolved configuration.
  - Supports `-WhatIf` and `-Force`.
- Updated `config/lab.env.example` to reference the new interactive script.
- Updated `.gitignore` to exclude local env files (`config/*.env.local`, `.env`, `*.env.local`).

## Verification
- `powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-Command 'scripts/lab/Initialize-DlpEnvironment.ps1'"` parsed successfully.
- Ran the script against a temporary env file with all dummy values and confirmed it set 52 variables and wrote the output env file without prompting.
- Removed temporary test artifacts.

## Usage
```powershell
# Interactive setup
.\scripts\lab\Initialize-DlpEnvironment.ps1

# Load existing file, prompt only for missing values, and persist
.\scripts\lab\Initialize-DlpEnvironment.ps1 -EnvFile .\config\lab.env.local -OutEnvFile .\config\lab.env.local
```

## Artifacts
- `scripts/lab/Initialize-DlpEnvironment.ps1`
- `config/lab.env.example`
- `.gitignore`
