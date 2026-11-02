# alpha1.4 validation

Date: 2026-11-02 (Asia/Shanghai). Executed locally on Windows.

## Results

- `python -m unittest discover -s tests -q`: 39 tests passed.
- `python scripts/audit_doctor.py`: 0 failures, 0 warnings; 31 required files,
  version/depth documentation and 26 Python/Bash rule names checked.
- `python -m compileall -q scripts tests`: passed.

Tests use temporary synthetic projects, a temporary Git repository and mocked dependency
tool responses. They cover retained/deleted historical secrets, bounded history,
multi-value redaction, exact baseline matching, risk-based depth, reasoned N/A,
evidence requirements, malformed output, timeout/error statuses, release gates,
dynamic cleanup, report rendering without overwrite, and missing findings requiring review.

## Limits

- No dynamic attacks against business projects were executed.
- No live package registry/CVE service was queried. Dependency tool integrations were
  tested with controlled responses, not every installed tool/version.
- Linux/macOS and the existing CI platform matrix were not executed locally.
- Bash remains a legacy fallback. Rule-name parity is not functional parity.
- Report validation checks structure and gates, not truth of evidence or complete redaction.
- Git history covers bounded HEAD ancestry and added text patch lines, not all refs,
  binary history or arbitrary encodings. Output/time caps return incomplete.
- Regex inventory and secret detection remain heuristic. Skipped artifacts and unknown
  interface totals require manual review. Templates are intentionally incomplete drafts.

## Migration

- `self_check --strict` now exits 2 for WARN/incomplete, 1 for FAIL, 0 otherwise.
- High status records now require evidence or reasoned N/A for every H item; H6/H8
  always require completion. Bare `"done"` is insufficient.
- Baselines require exact fingerprints; broad rule/file matches no longer suppress hits.
- Risk severity is independent from confidence; non-reproduction no longer halves deductions.
- New history/report capabilities are implemented in Python only.
