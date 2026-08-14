---
status: complete
---

# Summary: Add per-prompt instructions to env setup script

## Completed
- Enhanced `scripts/lab/Initialize-DlpEnvironment.ps1`:
  - Added a `Get-HelpText` function that returns step-by-step instructions for every `DLP_*` variable.
  - Each prompt now displays "How to obtain this value:" with concrete guidance, including:
    - Where to find existing values (Active Directory, config files, lab topology).
    - OpenSSL or PowerShell commands to generate values (root CA, admin CA, device-issuing CA, server cert/key, Ed25519 seed).
    - PowerShell snippets to extract AD object GUID/SID.
    - Commands to compute the approved privilege manifest digest.
    - Build command for `dlpctl.exe`.
  - Added `-NoHelp` switch to suppress instructions for experienced operators.

## Verification
- `Get-Command` parsed the updated script without errors.
- Ran the script against a temporary env file containing all 52 values and confirmed it completed without prompts and wrote the output env file.

## Artifacts
- `scripts/lab/Initialize-DlpEnvironment.ps1`
- `.planning/quick/20260814-env-setup-instructions/`
