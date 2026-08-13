---
date: 2026-08-14
slug: append-enrollment-flow
summary: Append a dedicated enrollment-flow section to the Hyper-V DLP startup guide
---

# Append the enrollment flow into `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md`

## Goal

Add a focused "Enrollment Flow" section to the end of `HYPERV-DLP-STARTUP-GUIDE.md` (before "Related Docs") that explains how `Invoke-Client01Runtime.ps1` obtains, uses, and cleans up the enrollment token automatically through LAB-DC01 trusted provisioning.

## Changes

1. Insert a new section after the existing "Cheat Sheet" section and before "Related Docs":
   - Explain the trust boundaries (hungdinh-lt → LAB-DC01 → LAB-CLIENT01).
   - Describe the automatic token acquisition via `-EnrollmentTokenProvider TrustedProvisioning`.
   - Show the DPAPI credential establishment step.
   - Document token cleanup behavior and the `-RetainEnrollmentToken` troubleshooting switch.
   - Provide a verification snippet to confirm the token is absent from the service registry after enrollment.

2. Update `STATE.md` "Quick Tasks Completed" table.

3. Commit the doc update atomically.

## Verification

- `HYPERV-DLP-STARTUP-GUIDE.md` contains the new "Enrollment Flow" section.
- Section references `-EnrollmentTokenProvider TrustedProvisioning` and `-RetainEnrollmentToken`.
- Section explains token cleanup and DPAPI credential creation.
- No manual copy-paste of `DLP_AGENT_ENROLLMENT_TOKEN` is described as required.
