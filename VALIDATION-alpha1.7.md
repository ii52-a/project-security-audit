# alpha1.7 validation — 2026-11-04

Local Windows / Python verification. No production target, live registry query or
dynamic exploitation was used. Prior alpha1.6 changes are retained.

## Executed checks

- `python -m unittest discover -s tests -q`: **73 tests passed** in 22.813 seconds.
  This includes 14 alpha1.7 tests and the 59 previous regression tests.
- `python scripts/audit_doctor.py --json`: 45 required files present, 8 checks passed,
  zero failures and warnings; active versions match alpha1.7.
- `python -m compileall -q scripts tests`: passed.
- `git diff --check`: no whitespace errors; Git reported normal CRLF/LF conversion notices.
- The guided end-to-end test executes local scanners, uses returned review templates,
  retains manual-review candidates and writes validated JSON/Markdown reports using
  the final request template. It supplies synthetic review evidence, not a real model judgment.
- History occurrence verification creates a temporary local Git repository and commit.
- Dependency tests use controlled tool responses and process mocks, not live advisory services.

## Fix verification

| Previous issue | alpha1.7 behavior and test |
|---|---|
| Moderate npm advisory disappeared after WARN normalization | Candidate survives adapter into triage with advisory ID, package and severity |
| Summary-only dependency output lacked actionable detail | Explicit summary-requires-review candidate; no fabricated advisory ID/version |
| Go config=null / cargo found/count/list contradictions passed | Incomplete/unknown; valid Go event stream remains supported |
| .github/.gitlab excluded by .git prefix | CI directories included; exact .git excluded |
| Same history secret repeated on one line shared ID | Column distinguishes occurrences; two independent C-IDs |
| Quoted Compose environment key and Python subscript DEBUG missed | Both recognized; commented Python assignment remains ignored |
| Zero coverage totals accepted for nonempty scope | File totals derived from snapshot; conflicting counts and nonexistent reviewed paths rejected |
| Resolved candidate could not link resolved finding | Matching resolved finding plus successful structured retest accepted; absent retest rejected |
| Progress queries repeatedly hashed source files | progress/file_inventory avoid hashing, explicitly return not-rechecked freshness |

## Reduced orchestration burden

- `run_pending` executes a bounded batch, saves after each check and resumes without
  automatically rerunning completed checks. Network authorization is never inferred.
- `next_action` returns actionable request skeletons, including finalization;
  `review_template` inserts actual candidate IDs and file choices.
- `finding_draft` copies candidate source information and creates a finding ID;
  severity, evidence, remediation and confirmation remain reviewer decisions.
- `write_evidence` writes the JSON artifact, calculates its hash and makes it available
  in the high review form. Scope changes invalidate the saved evidence association.
- File/interface coverage arithmetic is automatic. Interface inventory completeness
  still depends on review; an estimate discrepancy requires an explanation.
- Three profiles expose development-dependency scope as `dependency_include_dev`:
  quick=false, low/high=true. Tests verify the npm arguments for each setting.

These checks demonstrate fewer manual orchestration steps. No comparative experiment
between stronger and weaker models was performed; no claim is made that weaker models
now achieve equal vulnerability recall or judgment quality. No IO benchmark was run.

## Remaining boundaries

This is a local JSON CLI/Python API, not an installed MCP server. Business logic,
authorization and cross-file dataflow still need AI/manual reasoning. Config analysis
supports a conservative subset, not general YAML interpretation or taint analysis.
Dependency CLI/schema/version compatibility requires future live integration checks.

Content verification still costs IO on active operations; batching reduces repeated
checks but does not make concurrent target edits safe. Snapshots exclude configured
trees/symlinks and remain bounded at 50k files/1GiB. C-IDs can change after line movements.
Structural evidence validation and hashes do not prove review truth or successful remediation.
Reports retain unresolved candidates and never automatically approve release.

Linux/macOS were not exercised locally. Bash remains the legacy implementation.

## Migration

Create a new alpha1.7 state; older states are rejected instead of silently converted.
Coverage review now supplies reviewed_files, interfaces and interface_inventory_complete;
exported report count fields are unchanged. Existing evidence and reports should be kept
as historical records. Numerical scan budgets retain the three existing profiles.
