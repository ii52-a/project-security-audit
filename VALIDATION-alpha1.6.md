# alpha1.6 validation — 2026-11-04

Local Windows / Python validation; no production target or network exploit testing.

## Executed checks

- 59 regression tests passed, including 8 new evaluation regression tests covering E01-E09.
- audit_doctor: 41 required files present; zero failures/warnings.
- compileall completed successfully; git diff whitespace check passed.
- Replayed 21 scans / 57 tool checks against the same synthetic projects used for alpha1.5.
- Dependency malformed-schema probes use mocked outputs, not live registry/CVE services.

## Before / after

| Scenario | alpha1.5 | alpha1.6 |
|---|---|---|
| Confirmed candidate without linked finding | Finalized empty finding list | Rejected; requires confirmed finding_id |
| High evidence="checked" | Accepted | Rejected; requires structured artifact and integrity check |
| Manual-review candidate | Could disappear from findings | Retained as candidate and unresolved candidate |
| npm unexpected counts / cargo null list / Composer unsupported list | PASS | WARN / parsing incomplete |
| Commented Python debug | FAIL | PASS |
| Compose list-form weak password | PASS | FAIL |
| Multi-value/Example/UTF16 fixture | 1 candidate | 4 candidates |
| Zero files scanned due to size cap | complete/no-candidates | complete/unknown + partial coverage |
| Same-length/mtime-preserving modification | Cache reused | Content hash invalidates cache |
| Refresh after payment-risk selection | Risk prompt lost | Risk focus retained |
| coverage.files=42 request | Traceback | JSON error, exit 2 |

Normal credential/config/history fixtures retain their expected results. The ~3MiB LF
fixture is skipped by quick/low and detected by high; high's 5MiB cap is unchanged.
The earlier CRLF fixture is ~6MiB and correctly remains excluded even in high.
Build-directory exclusions remain visible limitations rather than expanded scan scope.

## Scope of assurance

Tests prove these controlled cases, not general vulnerability detection accuracy. SQL
injection, object authorization and path traversal still require AI/manual analysis;
this release does not add a general taint/AST vulnerability engine. High artifacts
verify shape, provenance and consistency, not the truth of reviewer statements.
Content snapshots exclude configured trees, have 50k-file/1GiB bounds and add IO cost.
Compose environment parser supports a conservative subset; complex values stay unknown.
Python enhancements are not ported to legacy Bash. Linux/macOS and live dependency-tool
versions were not exercised locally.

## Migration

Start a new alpha1.6 state. Old states are rejected. Replace per-check dispositions with
candidate IDs; confirmed needs finding_id; second-pass needs analysis; high needs hashed
JSON artifacts. Existing alpha1.5 reports are preserved but may fail new high validation.
All three effort profiles retain their numerical scanning budgets.
