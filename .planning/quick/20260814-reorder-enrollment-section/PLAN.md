---
date: 2026-08-14
slug: reorder-enrollment-section
summary: Move the Enrollment Flow section to immediately precede the endpoint deployment section
---

# Reorder Enrollment Flow section

## Goal

Move the existing "Enrollment Flow" section so it appears immediately before the "Deploy and Start the Endpoint Agent Service on LAB-CLIENT01" section, and renumber all following sections consistently.

## Changes

1. Remove the current `## 13. Enrollment Flow` block from the end of the document (before Related Docs).
2. Insert it after `## 7. Verify the Management Server from LAB-CLIENT01` and before the current `## 8. Deploy and Start the Endpoint Agent Service on LAB-CLIENT01`.
3. Renumber sections so the document flows as:
   - 1. Prerequisites
   - 2. Verify VM State
   - 3. Start the Lab VMs (Warm Start)
   - 4. Cold-Start the Whole Lab
   - 5. Start the Database on LAB-SERVER01
   - 6. Start the Management Server on LAB-DC01
   - 7. Verify the Management Server from LAB-CLIENT01
   - 8. Enrollment Flow (moved)
   - 9. Deploy and Start the Endpoint Agent Service on LAB-CLIENT01
   - 10. Run Endpoint Service Smoke Tests
   - 11. Full Environment Reconcile
   - 12. Troubleshooting Quick Reference
   - 13. Cheat Sheet
   - Related Docs

## Verification

- `HYPERV-DLP-STARTUP-GUIDE.md` contains exactly one `## 8. Enrollment Flow` heading.
- `## 9. Deploy and Start the Endpoint Agent Service on LAB-CLIENT01` immediately follows it.
- Section numbers are sequential from 1 through 13.
