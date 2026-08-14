---
slug: env-setup-script
description: Create an interactive PowerShell script that prompts for missing or placeholder DLP environment variables and configures the current session.
---

# Plan: Interactive DLP environment setup script

## Goal
Replace manual, error-prone environment-variable entry with a single PowerShell script that:
1. Knows every `DLP_*` variable used by the Phase 1 lab.
2. Loads any existing `.env` file first.
3. Prompts the user for any variable that is missing, empty, or still contains a `REPLACE_*` placeholder.
4. Validates formats (hex length, file existence, URLs, drive letters) before accepting input.
5. Sets the variables in the current process.
6. Optionally writes the resolved values to a local `.env` file for reuse.

## Deliverables
- `scripts/lab/Initialize-DlpEnvironment.ps1` — interactive setup script.
- Update `config/lab.env.example` comments to reference the new script.
- `SUMMARY.md` for this quick task.

## Design notes
- Keep the existing `Set-DlpEnvironment.ps1` behavior intact (non-interactive defaults). The new script is a wrapper/orchestrator.
- Group prompts by role (server, AD, provisioning, agent, orchestration) so the user is not overwhelmed.
- Use secure input (`Read-Host -AsSecureString`) for passwords and private-key seeds, displaying `[redacted]` when showing a summary.
- Provide a `-SkipValidation` switch for cases where files will be created later.
- Provide `-OutEnvFile <path>` to persist the resolved configuration.
- Mark the generated local file as ignored by existing `.gitignore` patterns (`*.local`, `.env`).

## Verification
- Run the script in dry-run mode (`-WhatIf`) to confirm it would prompt for the expected variables.
- Run with known-good env values to confirm all variables are set and no prompts appear.
- Confirm `config/lab.env.example` still parses correctly.
