# Changelog

## alpha1.2

### English-first migration

- `SKILL.md` and `references/*.md` are now authoritative engineering English.
- The synchronized Chinese human manual moved to `.chinese/`; agents are explicitly told
  not to load it as execution context.
- Added normative RFC 2119 language, explicit stage exit criteria, decision-precedence
  rules, and a report output contract to improve model comprehension.
- Added an English README and translated CHANGELOG; the Chinese README and CHANGELOG remain
  under `.chinese/`.
- No detection behavior, script interface, or scoring rule changed in this release.

## alpha1.1

### Safety and consistency fixes

- Unified the workflow as ten stages (Stages 1–9 main flow, Stage 10 review pass) and
  removed conflicting "nine-stage" wording.
- Unified the non-reproduction downgrade rule: at most half a level, and only when the
  attack actually covered the relevant path.
- Made conclusion precedence explicit: "not releasable" hard red lines first, then
  "releasable after remediation", then "releasable". A/B/C/D now denote score bands only.
- Fixed the conflict between the ≤6-attempt account-lockout rule and the rate-limit probe:
  the probe uses a disposable account, at most 12 requests, after all session tests.
- Added a hard LLM tool-abuse constraint: mock/dry-run/disposable tenant only; no real
  deletion, bulk messaging, or payment.
- Added report evidence-redaction rules; reports default to `security-reports/`.
- Added "scope and limitations", Appendix A (interface inventory), and Appendix B
  (evidence-redaction record) to the report contract.
- Replaced hard-coded years in vulnerability-intelligence examples with placeholders.
- Fixed the pre-commit hook to catch `.env.local`, `.p12`, `.pfx`, and `id_rsa`.

### Cross-platform tooling

- Added `scripts/scan_secrets.py` and `scripts/self_check.py`: Python 3.9+,
  Windows/Linux/macOS, with `--json`, `--strict`, and `--skip-deps`.
- `self_check.py` fails closed when a scanner fails instead of reporting PASS.
- The bash `self_check.sh` gained `--strict`, scanner-failure handling, sensitive-file
  notices, and coverage for `.env`, YAML `debug: true`, and `.tsx` files.
- Aligned bash secret rules with Python and added `.pypirc`, Docker `auth`, and Slack
  webhook rules.
- Updated dynamic-test templates for MySQL/PostgreSQL/SQL Server blind injection, UUID and
  numeric IDs, and portable temporary-directory/base64 handling.

### Engineering

- Added `tests/test_smoke.py` covering secret scanning, debug switches, weak deployment
  passwords, sensitive files, and `--strict` exit behavior.
- Added GitHub Actions CI: Ubuntu/Windows × Python 3.9/3.12, tests plus bash syntax checks.
- Added `.gitattributes`, `.gitignore`, `README.md`, `VERSION`, and `CHANGELOG.md`.

## alpha1.0

- Initial snapshot: ten-stage security-audit workflow, 11 reference files, and two bash
  scripts.
- Included secret scanning, server/API/advanced checklists, vulnerability-intelligence
  verification, the AI attack authorization gate and red lines, P0–P3 five-dimension
  scoring, the report template, and the A/B/C self-review cadence.
