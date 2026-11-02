# security-audit

Current version: **alpha1.5**

Evidence-based security review with quick, comprehensive-low and comprehensive-high depths.
Risk drives depth; size informs budget. Explicit choices are preserved. Dynamic attacks
require authorization and isolation. Structure and performance review are optional.

Run commands from this skill directory with Python 3.9+:
```
python scripts/audit_depth.py PROJECT --json --risk payment --risk sensitive-data
python scripts/scan_secrets.py PROJECT --json
python scripts/audit_history.py PROJECT --commits 200 --timeout 60
python scripts/self_check.py PROJECT --strict --json
python scripts/audit_report.py report.json --render report.md
python scripts/audit_report.py current.json --compare previous.json
python -m unittest discover -s tests -v
python scripts/audit_doctor.py
```

Self-check strict exits: 0 no FAIL/WARN, 1 FAIL, 2 incomplete/WARN. These are check
outcomes, not release authorization. History exits: 0 no candidates in bounded scan,
1 candidates, 2 incomplete. Git scanning never checks out files or runs external diff tools.
It scans added patch lines reachable from HEAD, not all branches or binary history.

Secret baselines require exact fingerprints; broad file/rule suppression is no longer
accepted. Candidates still need manual classification. Excluded artifacts and binary
contents need separate review. Raw third-party audit output is omitted from reports.

See references/report-format.md and assets/ for JSON contracts and templates. Reports
must be redacted and kept out of Git. English is authoritative; .chinese is the human manual.
Bash scripts remain legacy fallbacks with rule-name parity only; alpha1.5 enhancements
are Python-only. CI covers Ubuntu/Windows; local checks do not prove every platform.

## alpha1.5 controller

New audits can use `python scripts/audit_control.py request.json` or JSON on stdin.
`{"action":"describe"}` lists calls; `{"action":"profiles"}` returns all depth defaults.
See [controller contract](references/controller.md) for state, evidence and limitations.
This release provides local JSON CLI/Python tools; MCP installation is not included.
