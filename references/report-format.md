# Structured report contract — alpha1.4

Copy assets/quick-report.json or assets/comprehensive-report.json. Templates deliberately
fail validation until populated and redaction_reviewed=true. Do not persist raw evidence.

Required: project, date, scope, limitations, depth, coverage, checks, findings, dynamic.
Coverage includes files/interfaces {reviewed,total}; totals must be established, not guessed.
If totals are unknown, keep the record as a draft and explain limitations in Markdown;
do not turn an unknown total into zero to pass validation.
Checks use pass/fail/error/skipped/not-applicable, plus evidence or a reason.
Each finding has a stable id, title, P0-P3 severity, high/medium/low confidence, status
(confirmed/suspected/not-reproduced/resolved), location, redacted evidence and remediation.
Evidence should include impact/preconditions and regression verification when resolved.
Use stable IDs across audits; missing IDs in a later report require review, not auto-closure.

Dynamic: executed=false requires reason. executed=true requires authorization, isolation,
tests (plan, hypothesis, outcome and evidence) and cleanup records. Quick forbids execution.
High adds high_only with H1-H8 evidence or reasoned N/A; H6/H8 cannot be N/A.
coverage_complete is a reviewer assertion for the agreed scope, not inferred from counts.
roadmap, score, structure and performance are optional comprehensive fields.

Commands (paths relative to the skill):
```
python scripts/audit_report.py report.json
python scripts/audit_report.py report.json --render report.md
python scripts/audit_report.py current.json --compare previous.json
```
Renderer refuses to overwrite an existing file. Validator checks structure and gates;
it cannot establish evidence truth or guarantee redaction. Review both before delivery.
Exit 0 means valid; 1 means validation failure; 2 means I/O/input error.
