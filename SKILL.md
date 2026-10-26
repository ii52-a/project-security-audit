---
name: security-audit
description: >-
  Perform a structured security audit of a project directory: static review, authorized
  AI-driven attack validation, vulnerability-intelligence checks, risk scoring, and an
  actionable report. Use for security audits, security assessments, vulnerability scans,
  penetration/red-team exercises, secret or hard-coded credential checks, API security
  reviews, project risk assessments, recent CVE checks, pre-release self-reviews, and
  structure or performance reviews. Also use when the user asks informal questions such
  as "check this project for problems", "review it before launch", "attack it like an
  attacker", or "what recent vulnerabilities affect us", even if the word "security" is
  not used. The user may write in any language; map equivalent requests to this workflow.
---

# Security Audit Skill

> **Agent execution note.** This file and `references/*.md` are the authoritative
> English specification for execution. `.chinese/` contains the Chinese human-facing
> manual. Agents MUST NOT read or use `.chinese/` as execution context unless the user
> explicitly asks for the Chinese text. If the English and Chinese versions disagree,
> the English version prevails.

## 1. Purpose

Audit a target directory end to end: static review, authorized dynamic validation,
vulnerability-intelligence correlation, risk scoring, and a report with reproducible
evidence and a remediation roadmap.

The audit produces one Markdown report. Findings MUST be evidence-based. Speculation
MUST be labeled as requiring manual review, never presented as a confirmed vulnerability.

## 2. Normative operating rules

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as defined in RFC 2119.

- **RO-1 — Static review is read-only.** During static review, do not modify or delete
  project files. Remediation is written in the report only. Dynamic tests may create
  temporary data, but all canaries, test accounts, roles, listeners, and temporary files
  MUST be removed during cleanup.
- **RO-2 — Evidence before conclusions.** Every finding MUST include either a
  `file:line` reference with a code excerpt, or an HTTP request/response or command
  transcript for dynamic evidence. Do not report a finding that you cannot locate or
  reproduce. Mark unconfirmed items as `MANUAL REVIEW REQUIRED`.
- **RO-3 — Redact before persistence.** Reports MUST mask credentials, tokens, cookies,
  and personal data. Retain at most the first and last four characters of a secret;
  replace `Authorization`, `Cookie`, `Set-Cookie`, password, and token values with
  `[REDACTED]`; mask phone numbers, email addresses, national IDs, and bank cards. Raw
  evidence MUST remain in an access-controlled local location and MUST NOT be committed.
- **RO-4 — Define scope and coverage.** Before starting, establish the target directory,
  exclusions, file/time budget, and sampling rules. The report MUST include a
  "Scope and limitations" section listing what was not examined and why. "Not found"
  MUST NOT be reported as "not present".
- **RO-5 — Dynamic testing requires all three preconditions.** Do not execute dynamic
  attack tests unless all of the following hold simultaneously:
  1. **Authorization.** The target is a local or test environment owned by the user, and
     the user has explicitly authorized attack testing.
  2. **Isolation.** The target does not contain real user data and does not connect to a
     production database or production third-party accounts.
  3. **Within red lines.** All tests comply with the non-destructive payload, rate-limit,
     and no-third-party rules in `references/attack-testing.md`.
  If any precondition fails, skip dynamic testing, perform static review only, and record
  the reason in the report.
- **RO-6 — Stop on production indicators.** If you detect a real domain, a public
  production database, real user records, or any other production indicator, terminate
  dynamic testing immediately, even if the environment is already running.
- **RO-7 — Report placement.** Write the report to `security-reports/<project>-<date>.md`
  or a user-specified location. Confirm that the destination is writable and is not
  committed to version control. If the user requires the report inside the audited
  repository, warn about `.gitignore` and obtain consent before writing.
- **RO-8 — Fail closed.** If a scanner, dependency-audit tool, or required command fails,
  record a failure or warning; do not reinterpret the failure as a clean result.

## 3. Execution environment

- Static review requires only file-read access.
- Prefer the Python tools (`python scripts/*.py`), which support Windows, Linux, and
  macOS and require Python 3.9 or newer.
- `scripts/*.sh` are bash fallbacks for Linux, macOS, and Git Bash. On Windows, do not
  assume that the system `bash.exe` is usable; it may be a WSL launcher without a
  distribution.
- Dynamic testing additionally requires `curl`. Optional tools: `jq`, `python`.
- Dependency-audit tools (`npm`, `pip-audit`, `govulncheck`, `cargo`, `composer`) are
  optional and depend on the project stack. If a tool is unavailable, record
  `NOT EXECUTED` in the report.
- Commands in the references use bash syntax. On Windows, use Git Bash or translate them
  to equivalent PowerShell without changing their semantics.

## 4. Workflow (ten stages)

Stages 1–9 are the main workflow. Stage 10 is a review pass for high-risk modules. Stage
10 MAY be scoped down, but any skipped scope MUST appear in "Scope and limitations".

### Stage 1 — Reconnaissance

1. List the target tree to depth 3–4 and identify the stack: language, framework, build
   tool, runtime, and deployment configuration.
2. Locate entry points, route and interface definitions, configuration files (`.env`,
   `config.*`, `docker-compose.yml`, `nginx.conf`), dependency manifests and lock files,
   CI/CD configuration, and Dockerfiles.
3. Identify the external attack surface: listening ports, web services, API routes,
   static asset directories, and administrative interfaces.
4. Write the results into the report's "Project overview" section. Later stages depend on
   this baseline.

**Exit criterion:** the project overview identifies the stack, entry points, exposed
surface, and key configuration files.

### Stage 2 — Secrets and hard-coded credentials

1. Run `python scripts/scan_secrets.py <target>` (preferred, cross-platform). If Python
   is unavailable, run `bash scripts/scan_secrets.sh <target>`. The rules cover cloud
   access keys, private keys, connection strings, JWT secrets, platform tokens, and
   related patterns (20+ rule classes).
2. Manually confirm every candidate. Regex rules produce false positives (examples,
   fixtures, placeholders such as `xxx`) and miss patterns such as sensitive values in
   logs, internal addresses in front-end bundles, and paths in error stacks.
3. Check `.gitignore` coverage and Git history. A secret that was ever committed MUST be
   treated as compromised and rotated; deleting the file alone is not remediation.
4. Follow `references/secrets-hijack.md` for the full checklist.

**Exit criterion:** every scanner candidate is classified as confirmed, false positive,
or manual review; Git history and ignored files are checked.

### Stage 3 — Server and runtime vulnerabilities

Use `references/server-vulns.md` to check injection classes, authentication and session
management, authorization, file handling, SSRF/CSRF, security headers, TLS, container and
deployment configuration, and dependency vulnerabilities.

**Exit criterion:** each category in the checklist has an explicit result or a recorded
justification for omission.

### Stage 4 — Interface review

1. Enumerate every interface: routes, RPC methods, GraphQL operations, WebSocket events,
   message-queue consumers, scheduled jobs, and CLI entry points.
2. For each interface, answer four questions: **Who can call it? Is input validated? Is
   output redacted? Is it rate-limited?**
3. Use `references/api-audit.md` to check authentication, authorization and object-level
   access control, input and output handling, CORS, file upload/download, rate limiting,
   and webhook signature verification. The resulting suspected-vulnerability list is the
   primary input to Stage 7.

**Exit criterion:** the interface inventory is complete and stored in Appendix A; each
interface has answers to the four questions.

### Stage 5 — Advanced risk review

Use `references/advanced-risks.md` to cover dimensions that the basic checklists do not:
cryptography misuse, race conditions and concurrency defects, LLM/AI application risks
(prompt injection, tool abuse, excessive agency), GraphQL and WebSocket, internal trust
in microservices, cloud and IAM, front-end risks (postMessage, localStorage, source maps),
mobile clients, and supply-chain attacks.

**Exit criterion:** each section of the advanced checklist is marked checked, not
applicable, or manual review required.

### Stage 6 — Recent vulnerability intelligence

Use `references/vuln-intel.md`.

1. Extract a component inventory with exact versions from the Stage 1 inventory and lock
   files. Do not rely on loose ranges in manifests.
2. If network access is available, run the relevant automated audit first
   (`npm audit --omit=dev`, `pip-audit`, `govulncheck`, `cargo audit`, `trivy fs`), then
   search vendor advisories, GitHub Security Advisories, and NVD for recent CVEs. Mark
   entries with known in-the-wild exploitation with `[EXPLOITED]`.
3. For every candidate, verify the affected version range against the actual version and
   check whether the triggering condition applies. Record the result in the intelligence
   table.
4. For affected injection or RCE issues with a public proof of concept, add a
   non-destructive, red-line-compliant attack hypothesis to Stage 7. If a safe variant is
   impossible, perform static confirmation only and mark it `NOT TESTED`.

**Exit criterion:** every component with a candidate CVE has a version/condition verdict:
affected, not affected, or manual review required.

### Stage 7 — Authorized dynamic validation

**Read the authorization gate and red lines in `references/attack-testing.md` before
executing any command.**

1. **Authorization check.** Confirm that the target is user-owned and non-production and
   that the user has authorized attack testing. Terminate on production indicators.
2. **Environment preparation.** Start the application in an isolated environment, create
   two test accounts (A and B) for object-level authorization tests, and capture baseline
   responses. Before testing, ask the user to commit or tag the current work so that
   canaries and temporary changes can be reviewed with `git diff` and reverted.
3. **Hypotheses.** Combine the suspected issues from Stages 3–6 with the standard
   techniques in the attack manual. Assign each hypothesis an `ATK-xx` identifier.
4. **Execution.** Validate authentication bypass, IDOR, injection with non-destructive
   payloads and canaries, SSRF with a local listener, rate limiting, race conditions, mass
   assignment, open redirects, CORS, and other applicable techniques. Record the complete
   request and response for every attempt.
5. **Cleanup.** Delete canary data and test accounts, restore any role or permission
   changes made during mass-assignment tests, stop listeners, and remove cookie jars and
   temporary files.
6. **Conclusions.** Classify each hypothesis as **Confirmed** (with dynamic evidence),
   **Excluded** (not reproduced), or **Not verifiable** (with the reason).

**Exit criterion:** every hypothesis has one of the three conclusions, and the cleanup
checklist is complete.

### Stage 8 — Risk assessment and scoring

Use `references/risk-standards.md`.

1. Assign P0–P3 to static, dynamic, and intelligence findings. Mark dynamically confirmed
   findings `[VERIFIED]`; their severity MUST NOT be downgraded. For a static suspicion
   that was not reproduced, mark it `NOT REPRODUCED` and downgrade by at most half a
   level, only if the attack actually covered the relevant path.
2. Score five dimensions: attack-surface control, authentication and access control, data
   protection, dependency and supply-chain health, and operations and incident response.
   Produce a weighted total from 0 to 100. Every deduction MUST cite the finding IDs it
   corresponds to.
3. Apply the conclusion precedence in `risk-standards.md` Section 4: check the
   "not releasable" hard red lines first, then "releasable after remediation", and only
   then allow "releasable".

**Exit criterion:** every finding has a severity, every score deduction is traceable, and
the conclusion follows the mandated precedence.

### Stage 9 — Structure and performance review

1. Use `references/structure-optimization.md` to assess structure and list concrete
   optimization items.
2. Use `references/performance.md` to list performance issues and recommendations. These
   are advisory, not vulnerabilities; do not mix them into the P0–P3 finding table.

**Exit criterion:** structure and performance are reported in separate sections with
evidence and effort estimates.

### Stage 10 — High-risk review pass

For high-risk modules, apply the relevant prompts in `references/audit-prompts.md`
(12 categories, including cryptography, race conditions, and LLM/agent risks). Answer
each prompt against the actual code context. Do not skip a prompt without recording
`not applicable` or `manual review required`.

**Exit criterion:** every selected prompt has an answer, and unresolved items are listed
for manual review.

## 5. Quick mode: pre-release self-review

When the user asks for a self-review, self-check, security check, or pre-release check
without requesting a full audit, do not run the full ten-stage workflow. Use the A-track
in `references/self-review.md`.

1. Prefer `python scripts/self_check.py <project> --strict` (cross-platform; returns
   non-zero on FAIL). If Python is unavailable, run
   `bash scripts/self_check.sh <project> --strict`. The check covers secret candidates,
   dependency audit, Git hygiene, debug switches, and unsafe deployment defaults.
2. Run `git diff` against the previous release tag and select changes touching
   authentication, login, permissions, upload, payment, or configuration. Apply the
   four questions to each changed file.
3. Complete the A-track manual checklist and write a lightweight report to
   `security-reports/self-review-<date>.md`. Do not write it to the repository root.
4. **Report, do not exploit.** If a suspected exploitable issue is found, stop and
   recommend a full ten-stage audit. The quick mode's job is early detection, not
   exploitation.

## 6. Report contract

The report MUST be Markdown and MUST contain the following sections. Use the exact
heading order unless the user requests a different structure.

```markdown
# Security Audit Report: <project>

- Audit date / Scope (directories) / Stack / Skill version / Dynamic testing: yes|no and authorization note
- Total score: __ / 100 (score band: A/B/C/D)
- Overall conclusion: releasable | releasable after remediation | not releasable

## 1. Project overview
## 2. Scope and limitations
## 3. Recent vulnerability intelligence
## 4. Findings and risks (P0 -> P3; [VERIFIED] where applicable)
## 5. Dynamic attack-test record
## 6. Score breakdown
## 7. Checked with no findings
## 8. Structure assessment and optimization items
## 9. Performance analysis
## 10. Remediation roadmap and follow-up review cadence
## Appendix A. Interface inventory
## Appendix B. Evidence-redaction record
```

Each finding MUST use this structure:

```text
[P1] <title>
Location: <file:line> or <method> <path>
Issue: <what is wrong and why>
Exploitation: <preconditions, steps, and impact>
Evidence: <code excerpt or request/response; redacted>
Remediation: <specific code or configuration change and regression test>
```

**Pre-write redaction check:** secrets show at most four leading and four trailing
characters; `Authorization`, `Cookie`, `Set-Cookie`, password, and token values are
`[REDACTED]`; PII is masked; internal hostnames are removed while preserving the subnet
when useful. Raw evidence stays in the controlled local directory and MUST NOT be
attached to the report or committed to Git.

## 7. Severity definitions

The authoritative definitions are in `references/risk-standards.md`. The table below is a
quick reference only.

| Severity | Definition | Example |
|---|---|---|
| P0 Critical | Exploitable without special conditions; leads directly to data disclosure, authorization bypass, or system compromise | Hard-coded production key, verified SQL injection, unauthenticated admin API |
| P1 High | Exploitable with preconditions, or has high-impact disclosure | Horizontal privilege escalation, secrets in logs, disabled certificate validation |
| P2 Medium | Requires specific conditions or has limited impact | Missing security headers, no rate limiting, directory listing |
| P3 Low | Hardening recommendation | Outdated dependency, internal information in comments |

## 8. Version and regression

- Current version: **alpha1.2**; see `CHANGELOG.md` and `VERSION`.
- After changing a rule or script, run `python -m unittest discover -s tests -v`. CI runs
  the same suite on Ubuntu and Windows with Python 3.9 and 3.12.
- When adding or changing a detection rule, update both the Python and bash
  implementations, or record the intentional divergence in `CHANGELOG.md`.
- The Chinese human manual is in `.chinese/`. It is documentation, not execution context.

## 9. Reference index

| File | When to read |
|---|---|
| `references/server-vulns.md` | Before Stage 3 |
| `references/api-audit.md` | Before Stage 4 |
| `references/secrets-hijack.md` | Before Stage 2 |
| `references/advanced-risks.md` | Before Stage 5 |
| `references/vuln-intel.md` | Before Stage 6 |
| `references/attack-testing.md` | Before Stage 7 (authorization gate and red lines) |
| `references/risk-standards.md` | Before Stage 8 |
| `references/structure-optimization.md` | Before Stage 9 |
| `references/performance.md` | Before Stage 9 |
| `references/audit-prompts.md` | Stage 10 and high-risk review |
| `references/self-review.md` | Quick mode |
| `scripts/scan_secrets.py` | Stage 2 preferred implementation |
| `scripts/self_check.py` | Quick mode preferred implementation |
| `scripts/scan_secrets.sh` | Stage 2 bash fallback |
| `scripts/self_check.sh` | Quick mode bash fallback |
| `tests/test_smoke.py` | Regression tests after script changes |
