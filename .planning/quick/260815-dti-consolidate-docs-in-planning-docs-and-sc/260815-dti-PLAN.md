---
title: Consolidate planning docs and script documentation
description: Establish canonical documentation and script entrypoints, align ownership and cross-links, and remove only safely redundant operator prose without changing runtime behavior.
created: 2026-08-15
quick_id: 260815-dti
phase: quick-260815-dti-consolidate-docs-in-planning-docs-and-sc
plan: 01
type: execute
wave: 1
depends_on: []
autonomous: true
files_modified:
  - .planning/docs/README.md
  - .planning/docs/LAB-SETUP-GUIDE.md
  - .planning/docs/HYPERV-DLP-STARTUP-GUIDE.md
  - .planning/docs/HYPERV-VM-START-GUIDE.md
  - .planning/docs/LAB-SERVER01-SETUP.md
  - scripts/README.md
  - scripts/lab/README.md
estimate:
  tokens: 18000
  raw_tokens: 18000
  tasks: 2
  confidence: low
must_haves:
  truths:
    - "A reader entering .planning/docs can identify the correct start-here, daily-operation, reference, security, and ADR document without searching the repository."
    - "A reader entering scripts can identify the supported operator entrypoints and distinguish them from evidence helpers, tests, and scripts normally invoked by another orchestrator."
    - "Every current lab script is documented, and every documentation link changed by this plan resolves from its containing file."
    - "Unique prerequisites, safety warnings, expected outcomes, and troubleshooting guidance remain available after duplicate prose is consolidated."
    - "No PowerShell, Python, Rust, configuration, or runtime contract changes as part of this documentation-only quick task."
    - "Pre-existing user changes remain untouched and unrelated paths are absent from this task's commits."
  artifacts:
    - path: .planning/docs/README.md
      provides: Canonical documentation index and ownership map
    - path: scripts/README.md
      provides: Canonical repository script index and supported entrypoints
    - path: scripts/lab/README.md
      provides: Complete lab-script catalog with correct repository-relative documentation links
    - path: .planning/docs/LAB-SETUP-GUIDE.md
      provides: Canonical first-time lab setup sequence
    - path: .planning/docs/HYPERV-DLP-STARTUP-GUIDE.md
      provides: Canonical daily DLP lab startup sequence
    - path: .planning/docs/HYPERV-VM-START-GUIDE.md
      provides: Canonical VM power-management procedure
    - path: .planning/docs/LAB-SERVER01-SETUP.md
      provides: Canonical PostgreSQL host provisioning and migration procedure
  key_links:
    - from: .planning/docs/README.md
      to: .planning/docs/LAB-SETUP-GUIDE.md
      via: Start-here link and responsibility table
    - from: .planning/docs/LAB-SETUP-GUIDE.md
      to: scripts/README.md
      via: Repository script entrypoint link
    - from: scripts/README.md
      to: scripts/lab/README.md
      via: Lab operations index link
    - from: scripts/lab/README.md
      to: .planning/docs/README.md
      via: Correct ../../.planning/docs relative link
---

# Quick Plan: Consolidate `.planning/docs` and `scripts`

<objective>
Create a clear two-level navigation system for project documentation and scripts, then align the operator guides around explicit ownership boundaries so duplicated instructions have one canonical home.

Purpose: Operators should know where to start and which procedure is authoritative, while existing safety and troubleshooting guidance remains intact.

Output: Two new directory indexes plus focused cross-link and catalog corrections in the existing operator documentation.
</objective>

<context>
@.planning/STATE.md
@.planning/docs/
@scripts/
@.planning/quick/20260814-lab-setup-guide/PLAN.md
@.planning/quick/20260814-lab-setup-guide/SUMMARY.md
</context>

## Scope and safety contract

- Treat `.planning/docs/LAB-SETUP-GUIDE.md` as the first-time setup entrypoint already established by the completed lab-setup quick task; this plan improves navigation and ownership rather than replacing that decision.
- Do not rename, move, or delete existing documentation or scripts. Stable paths are part of the operator contract and historical references depend on them.
- Do not modify any `.ps1`, `.psm1`, `.py`, Rust, configuration, or deployment file. Inventory script behavior from the files, but consolidate only README and Markdown content.
- `.planning/docs/PEM-KEY-GUIDE.md` has pre-existing user edits. Read it to preserve its canonical PKI role, but do not modify or stage it in this task.
- Before editing, run `git status --short` and require every tracked path in `files_modified` to be clean. If any target has acquired user changes, stop and preserve it rather than overwriting or folding those changes into this task.
- Commit with exact pathspecs. Existing dirty paths outside `files_modified` must remain unstaged and uncommitted; never use `git add -A`, `git add .`, or a repository-wide commit.

## Canonical ownership map

| Concern | Canonical artifact | Consolidation rule |
| --- | --- | --- |
| Documentation navigation | `.planning/docs/README.md` | List every current operator/reference/security document and ADR; link to the owner rather than restating its procedure. |
| First-time lab setup | `.planning/docs/LAB-SETUP-GUIDE.md` | Keep the end-to-end setup order and setup-specific checks; delegate detailed environment, PKI, VM power, database, and daily startup procedures. |
| Daily lab startup | `.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md` | Keep warm/cold DLP service startup and runtime verification; direct first-time provisioning back to the setup guide. |
| VM power operations | `.planning/docs/HYPERV-VM-START-GUIDE.md` | Keep generic Hyper-V state/start/stop/cold-start commands only. |
| Environment contract | `.planning/docs/ENV-VARS.md` | Remains the authoritative variable list and value-acquisition reference; do not duplicate its full tables elsewhere. |
| PKI material | `.planning/docs/PEM-KEY-GUIDE.md` | Remains the authoritative PEM/key generation and mapping guide; preserve its existing user edits. |
| PostgreSQL host | `.planning/docs/LAB-SERVER01-SETUP.md` | Keep native PostgreSQL provisioning, access controls, and migration verification. |
| Development log debugger | `.planning/docs/DLP-LOG-DEBUG-SERVICE.md` | Keep isolated debugger lifecycle and security constraints separate from normal endpoint deployment. |
| Security model | `.planning/docs/THREAT-MODEL.md` | Index as security reference; do not blend it into operator runbooks. |
| Architecture decisions | `.planning/docs/adrs/ADR-001-*.md` through `ADR-010-*.md` | Index each ADR by exact filename and title; do not rewrite historical decisions. |
| Script navigation | `scripts/README.md` | Identify public operator runners and route readers to the lab or evidence collection. |
| Lab command catalog | `scripts/lab/README.md` | Document every current `.ps1` and `.py` file once, including invocation role, prerequisites, and a parameter-valid example. |

<tasks>

<task type="tracer">
  <name>Task 1: Create canonical indexes and complete the lab-script catalog</name>
  <precondition>`git status --short -- .planning/docs/README.md scripts/README.md scripts/lab/README.md` reports no tracked modifications; the two new README paths do not contain uncommitted user content.</precondition>
  <reversibility rating="reversible">The indexes and catalog links are local documentation contracts that can be changed without migrating data or runtime consumers.</reversibility>
  <files>.planning/docs/README.md, scripts/README.md, scripts/lab/README.md</files>
  <action>Create `.planning/docs/README.md` as the documentation front door with a brief start-here route, the canonical ownership map above, separate operator/reference/security/ADR sections, and a link for every current Markdown file under `.planning/docs` (excluding the index itself). Create `scripts/README.md` as the script front door: name `scripts/verify-phase1-evidence.ps1` as the supported Phase 1 evidence runner, describe `scripts/evidence/Phase1.Evidence.psm1` and the two evidence test files as implementation/test support rather than alternative operator commands, and route lab work to `scripts/lab/README.md`. Update `scripts/lab/README.md` from the live file inventory: add exact entries for `Debug-TrustedProvisioningTls.ps1`, `Rotate-DlpDeviceIssuingCa.ps1`, and `Rotate-DlpServerCert.ps1`; retain every existing script entry and unique warning; label scripts that are normally orchestrator-invoked versus manually invoked; and correct documentation links to resolve from `scripts/lab/` through `../../.planning/docs/`. Do not add wrappers, aliases, renamed copies, or script-body changes because the current entrypoints have distinct operational roles. Stage and commit only these three paths, using an exact path-scoped commit and confirming its file list before proceeding.</action>
  <verify>
    <automated>rtk powershell -NoProfile -Command "$docsRoot=(Resolve-Path '.planning/docs').Path; $index=Get-Content -Raw '.planning/docs/README.md'; $missingDocs=@(Get-ChildItem '.planning/docs' -Recurse -Filter '*.md' -File | Where-Object FullName -ne (Join-Path $docsRoot 'README.md') | Where-Object { $relative=$_.FullName.Substring($docsRoot.Length+1).Replace('\','/'); $index -notmatch [regex]::Escape('('+$relative+')') }); if($missingDocs){ throw ('Documentation index omissions: '+(($missingDocs.Name)-join ', ')) }; $actual=@(Get-ChildItem 'scripts/lab' -File | Where-Object Extension -in '.ps1','.py' | ForEach-Object Name | Sort-Object); $documented=@(Select-String -Path 'scripts/lab/README.md' -Pattern '^###\s+(.+\.(?:ps1|py))$' | ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object); $delta=@(Compare-Object $actual $documented); if($delta){ throw ('Lab script catalog mismatch: '+(($delta | Out-String).Trim())) }; if(-not (Select-String -Quiet -Path 'scripts/lab/README.md' -Pattern '\]\(\.\./\.\./\.planning/docs/')){ throw 'Lab README has no repository-correct planning-doc link' }"</automated>
  </verify>
  <done>Both directories have an obvious canonical README; the documentation index covers every current doc and ADR; the lab README covers all 16 current lab scripts exactly once, including the three previously omitted scripts; its planning-doc links resolve from `scripts/lab`; and the commit contains only the three declared Markdown files.</done>
</task>

<task type="auto">
  <name>Task 2: Align operator-guide ownership, topology, naming, and cross-links</name>
  <precondition>`git status --short -- .planning/docs/LAB-SETUP-GUIDE.md .planning/docs/HYPERV-DLP-STARTUP-GUIDE.md .planning/docs/HYPERV-VM-START-GUIDE.md .planning/docs/LAB-SERVER01-SETUP.md` reports no tracked modifications.</precondition>
  <reversibility rating="reversible">The changes reorganize Markdown navigation and remove duplicated prose while leaving stable filenames and runtime contracts intact.</reversibility>
  <files>.planning/docs/LAB-SETUP-GUIDE.md, .planning/docs/HYPERV-DLP-STARTUP-GUIDE.md, .planning/docs/HYPERV-VM-START-GUIDE.md, .planning/docs/LAB-SERVER01-SETUP.md</files>
  <action>Align the four operator guides to the ownership map without flattening their distinct workflows. In `LAB-SETUP-GUIDE.md`, keep the complete first-time sequence, add direct links to `.planning/docs/README.md` and `scripts/README.md`, and replace only repeated specialist detail with a short handoff to its owner while retaining setup order, prerequisites, security warnings, and expected outcomes. In `HYPERV-DLP-STARTUP-GUIDE.md`, declare daily startup as its scope, link first-time provisioning to `LAB-SETUP-GUIDE.md`, link back to the docs index, and retain the service-order, enrollment, verification, cleanup, and troubleshooting details specific to a running lab. In `HYPERV-VM-START-GUIDE.md`, keep generic Hyper-V power operations and convert the related-project-doc entries into valid Markdown links to the DLP startup, setup, database, and docs-index owners. In `LAB-SERVER01-SETUP.md`, retain PostgreSQL provisioning and migration guidance, reconcile the stale statement that the management server is still moving to LAB-DC01 with the current topology recorded in STATE and the setup guide, and add links to the docs index and daily startup guide. Use exact current filenames in labels and destinations. A section may be shortened only after confirming its unique prerequisites, warnings, result checks, and troubleshooting remain in that file or are carried by the linked canonical owner. Do not modify the dirty `PEM-KEY-GUIDE.md` or any other file. Stage and commit only these four paths with an exact path-scoped commit, leaving all unrelated dirty paths untouched.</action>
  <verify>
    <automated>rtk powershell -NoProfile -Command "$files=@('.planning/docs/README.md','.planning/docs/LAB-SETUP-GUIDE.md','.planning/docs/HYPERV-DLP-STARTUP-GUIDE.md','.planning/docs/HYPERV-VM-START-GUIDE.md','.planning/docs/LAB-SERVER01-SETUP.md','scripts/README.md','scripts/lab/README.md'); $broken=@(); foreach($file in $files){ $base=Split-Path -Parent (Resolve-Path $file).Path; $text=Get-Content -Raw $file; foreach($match in [regex]::Matches($text,'\[[^\]]+\]\(([^)]+)\)')){ $target=$match.Groups[1].Value; if($target -match '^(https?|mailto):' -or $target -like '#*'){ continue }; $pathPart=($target -split '#',2)[0]; if($pathPart -and -not (Test-Path (Join-Path $base $pathPart))){ $broken += ($file+' -> '+$target) } } }; if($broken){ throw ('Broken relative links: '+($broken -join '; ')) }; rtk git diff --check -- .planning/docs/README.md .planning/docs/LAB-SETUP-GUIDE.md .planning/docs/HYPERV-DLP-STARTUP-GUIDE.md .planning/docs/HYPERV-VM-START-GUIDE.md .planning/docs/LAB-SERVER01-SETUP.md scripts/README.md scripts/lab/README.md; if($LASTEXITCODE -ne 0){ exit $LASTEXITCODE }"</automated>
  </verify>
  <done>The setup, daily-startup, VM-power, and database guides each state a distinct purpose; their changed relative links resolve; current topology names LAB-DC01 as the management server and LAB-SERVER01 as PostgreSQL; removed duplication has a direct owner link without loss of unique safety or troubleshooting guidance; and the commit contains only the four declared operator guides.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
| --- | --- |
| Documentation to administrator | Runbooks can cause privileged VM, service, firewall, certificate, database, or secret-handling actions. |
| Script catalog to operator | Incorrect classification can lead an operator to run a diagnostic/helper directly when an orchestrator is required. |
| Dirty worktree to Git commit | Unrelated user changes can be staged or committed if the task uses broad Git pathspecs. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation Plan |
| --- | --- | --- | --- | --- | --- |
| T-Q260815-01 | Tampering | Operator runbooks | medium | mitigate | Retain security warnings, prerequisites, expected outcomes, and cleanup instructions; remove duplicate prose only with a direct canonical-owner link. |
| T-Q260815-02 | Elevation of privilege | Script navigation | medium | mitigate | Mark each script as operator-invoked, orchestrator-invoked, diagnostic, internal module, or test support so privileged helpers are not presented as interchangeable entrypoints. |
| T-Q260815-03 | Information disclosure | Secret-handling documentation | high | mitigate | Preserve runtime-only secret guidance and never add real credentials, tokens, certificate contents, or local secret paths beyond the existing documented contract. |
| T-Q260815-04 | Tampering | Git index and commit | high | mitigate | Require clean target paths, exact staging/commit pathspecs, commit file-list review, and no edits to pre-existing dirty paths such as `PEM-KEY-GUIDE.md` and the current script bodies. |
</threat_model>

## Multi-source coverage audit

| Source | ID | Item | Task | Status | Notes |
| --- | --- | --- | --- | --- | --- |
| GOAL | — | Consolidate docs in `.planning/docs` and scripts in `scripts` | 1, 2 | COVERED | Adds canonical indexes, completes inventory, aligns ownership and links. |
| REQ | — | No roadmap requirement IDs apply to this quick task | — | N/A | Quick work is intentionally outside phase requirement mapping. |
| RESEARCH | — | No research phase | — | N/A | Explicit quick-task constraint; existing repository evidence is sufficient. |
| CONTEXT | C-01 | Preserve all unique operational guidance | 2 | COVERED | Safe-removal rule requires owner links and preservation of warnings/checks/troubleshooting. |
| CONTEXT | C-02 | Preserve existing uncommitted user edits | 1, 2 | COVERED | Dirty targets fail preconditions; dirty PEM guide and script bodies are read-only. |
| CONTEXT | C-03 | Establish clear canonical entrypoints and indexes | 1 | COVERED | Creates `.planning/docs/README.md` and `scripts/README.md`. |
| CONTEXT | C-04 | Align cross-links and naming | 1, 2 | COVERED | Repairs lab README paths and normalizes owner links/file labels. |
| CONTEXT | C-05 | Reduce redundancy only where safe | 2 | COVERED | Specialist details move behind direct owner links only when unique context remains available. |
| CONTEXT | C-06 | Avoid runtime behavior changes except strictly necessary duplicate entrypoint consolidation | 1, 2 | COVERED | No script duplicates require consolidation; all runtime files are excluded. |
| CONTEXT | C-07 | Use path-scoped commits in the dirty shared worktree | 1, 2 | COVERED | Each task declares clean-target checks and exact commit pathsets. |

<verification>
1. Run both task-level automated checks from the repository root; each must complete in under 60 seconds.
2. Inspect `git diff --stat` and `git diff --name-only` for the seven allowed Markdown paths only. Existing unrelated status entries must match the pre-task baseline and remain unstaged.
3. Inspect each task commit with `git show --name-only --format=` and confirm it contains exactly that task's declared files.
4. Confirm `git diff --check` reports no whitespace errors in the seven allowed paths.
5. Confirm no `.ps1`, `.psm1`, `.py`, Rust, configuration, deployment, historical ADR, or historical summary file was modified by this quick task.
</verification>

<success_criteria>
- `.planning/docs/README.md` and `scripts/README.md` are the obvious entrypoints for their directories.
- Every current `.planning/docs/**/*.md` document and every current `scripts/lab/*.{ps1,py}` script is represented in its canonical index/catalog.
- The three previously missing lab scripts are documented and all `scripts/lab/README.md` planning-doc links resolve through `../../.planning/docs/`.
- Operator guides have distinct ownership, valid links, and topology consistent with STATE: management server on LAB-DC01 and PostgreSQL on LAB-SERVER01.
- All unique security warnings, prerequisites, expected results, cleanup steps, and troubleshooting guidance remain reachable.
- Runtime files and pre-existing user edits are byte-for-byte untouched; commits contain only their declared Markdown paths.
</success_criteria>
