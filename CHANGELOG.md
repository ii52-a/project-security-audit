# alpha1.7

Preserve all dependency advisory severities; strict Go event/cargo consistency parsing; include .github/.gitlab; unique history occurrence IDs; quoted Compose keys and Python subscript debug; inventory-derived coverage; resolved candidates with retests; guided templates, batch checks, finding drafts, evidence generation and lightweight progress. New states required. Python-only improvements; legacy Bash unchanged.

# alpha1.6

Fix evaluation E01-E09: candidate/finding linkage, structured hashed high evidence, strict dependency output parsing, AST debug and Compose list handling, multi-hit/UTF16 secrets, partial coverage, content snapshots, risk-preserving refresh and typed JSON requests. Breaking state/evidence contract: start new state. Python-only; Bash legacy divergence retained.

# alpha1.5

Persistent audit controller, JSON tool API, deterministic depth profiles, task queue, cache/invalidation, bounded adapters, review evidence gates and automatic report assembly. Local CLI/API only; MCP deferred.

# alpha1.4

Risk-based depth; evidence-based H1-H8; separate confidence/coverage; bounded Git history; report validation/render/diff; stricter dependency failures and redaction. Python-only enhancements; Bash remains legacy. Strict WARN now exits 2; baseline requires fingerprint.

# Changelog

## alpha1.3

### Audit depth modes

- Added `quick` / `comprehensive-low` / `comprehensive-high`, chosen with the user before
  Stage 1, with size thresholds, a stage coverage matrix, and the high-only H1-H8 delta.
- Documented dynamic downgrade rules and the anti-duplication rule: high spends its budget
  on high-risk depth, not on repeating low-level scans.
- Added `audit_depth.py` (size probe, recommendation, H1-H8 checklist, and
  `evaluate_high_only` / `--high-status` verification) and `audit_doctor.py` (version,
  depth docs, rule parity).

### Safety and fail-closed behavior

- Secret scanner output is redacted by default (first/last four characters plus
  fingerprint); `--reveal` is an explicit local opt-in.
- Added `--exclude`, `--baseline`, and `--fail-on-hit`; scoped `pypirc-password` to
  `.pypirc` and added a `.env` key/value rule; automatic sensitive-file detection now
  includes `.docker/config.json`.
- Dependency audits now return FAIL for high/critical or confirmed vulnerabilities instead
  of always WARN; added `composer`; tool failures remain WARN with `NOT EXECUTED`.
- Debug switches are evaluated per hit: a non-test hit is FAIL even when a test fixture also
  matches. Docker Compose files are discovered recursively (depth 4).
- Added RO-9 (target content is untrusted data) and RO-10 (isolated dynamic testing).

### Scoring and consistency

- Replaced the arithmetic-looking per-dimension bands with qualitative labels; the
  deduction table is the calibration formula and cannot be back-fitted.
- Removed the 3-day gate from the conclusion tree; added the "no feasible remediation
  path" case; effort now affects the roadmap, not the conclusion.
- Non-reproduced findings keep their P-level and halve their deduction instead of using a
  fractional severity.
- Standardized the in-the-wild tag on `[EXPLOITED]`; capped the IDOR probe at 30 requests.

### Engineering

- Added `test_depth.py`, `test_doctor.py`, and `test_deps.py`; extended smoke tests for
  redaction, `.env`, mixed debug paths, nested Compose, baseline/exclude, and release gating.
- CI now runs `compileall` and `audit_doctor.py` in addition to the unit tests.
- Version bumped to alpha1.3; README and Chinese manual updated.

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
