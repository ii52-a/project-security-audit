# Project Self-Review Workflow

A full audit (ten stages) is expensive and not suitable for daily execution. This document
defines a sustainable self-review cadence and serves as the skill's **quick mode**: when
the user asks for a self-review, self-check, or pre-release check, the agent runs the
A-track and produces a lightweight report without starting the full ten-stage workflow.

## A-track: pre-release quick check (target ≤15 minutes, excluding dependency-audit network time)

Run before every release, by a developer or an agent:

```bash
# 1. One-command self-check (secrets + dependency audit + Git hygiene + debug switches + unsafe deployment defaults).
# Prefer Python (Windows/Linux/macOS). --strict returns non-zero when a FAIL exists, suitable for CI.
python <skill-dir>/scripts/self_check.py <project-dir> --strict

# If Python is unavailable, use the bash version (Linux/macOS or Git Bash; the Windows built-in bash.exe may be a WSL launcher).
bash <skill-dir>/scripts/self_check.sh <project-dir> --strict

# 2. High-risk change review: select changes since the last review that touch security boundaries.
git diff --stat v<last-release-tag>..HEAD -- '*auth*' '*login*' '*permission*' '*upload*' '*pay*' '*config*'
# 3. Apply the four questions to new or changed interfaces.
git diff v<last-release-tag>..HEAD -- '*route*' '*controller*' '*api*'
```

For every changed file selected above, answer: **Does the new or modified interface enforce
authentication? Does external input reach a dangerous sink? Was a configuration default
changed? Were keys or credentials touched?** If any answer is unsatisfactory, trigger a
full audit.

### A-track checklist (manual items beyond the script)

| # | Check | Pass criterion |
|---|---|---|
| A1 | `self_check` reports no FAIL | Any FAIL blocks release until resolved; review every WARN manually |
| A2 | New dependencies checked against CVEs (use `vuln-intel.md` Section 3) | No unresolved high-severity issue |
| A3 | New environment variables documented and `.env.example` synchronized | Consistent |
| A4 | Database change scripts do not drop columns or alter permissions | Any such change requires separate review |
| A5 | New log statements do not print sensitive fields | Inspect the diff line by line |

Output: a lightweight report at `security-reports/self-review-<date>.md` (not the
repository root) containing the five checklist results, the risky-change list, and a
release/no-release conclusion.

## B-track: in-iteration security gates (each development iteration)

- New third-party package: check maintenance activity and known CVEs before installation;
  review `postinstall` scripts.
- New interface: apply the four questions from `api-audit.md` Sections 2–6 (who can call it,
  input validation, output redaction, rate limiting).
- Pre-commit secret blocking: see the pre-commit integration below.
- Changes affecting money, inventory, or permissions: require one reviewer, with emphasis
  on race conditions (whether "read then write" is atomic).

### Pre-commit integration (configure once, effective thereafter)

```yaml
# .pre-commit-config.yaml example
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.21.2
    hooks:
      - id: gitleaks
  - repo: local
    hooks:
      - id: no-secret-files-committed
        name: forbid committing .env/.pem/.key/.p12/.pfx/id_rsa
        entry: bash -c 'git diff --cached --name-only | grep -E "\.env(\..*)?$|\.pem$|\.key$|\.p12$|\.pfx$|(^|/)id_rsa" && exit 1 || exit 0'
        language: system
```

On Windows, pre-commit requires Git Bash or WSL to provide `bash`. Without bash, use a
Python hook or run gitleaks in CI.

## C-track: monthly deep review (≤2 hours)

1. Re-run Stage 2 (secrets, including Git-history delta), Stage 3 (server), and Stage 5
   (advanced) of the full skill. A full ten-stage run is not required every month.
2. Key-age check: every production credential MUST be rotated within 90 days; list expired
   credentials.
3. Least-privilege review: cloud IAM, database accounts, and server users that were
   temporarily elevated and never reduced.
4. Review the previous full audit report: are P0/P1 clear, and are P2 items being fixed
   incrementally?
5. Intelligence delta: use `vuln-intel.md` to re-search CVEs from the last 30 days for
   critical components.

## Escalation when self-review finds an anomaly

A/B-track self-review **finds issues; it does not exploit them**. If a suspected
exploitable vulnerability is found (injection, authorization bypass, secret disclosure),
stop the self-review, report it, and recommend a full ten-stage audit (including
authorized attack validation) to determine impact. Self-review is for early detection;
full audit is for confirmation.

## Agent execution order for quick mode

When the user asks for a self-review: read this file → run `self_check.py --strict`
(falling back to bash), run the Git-diff selection, complete the A-track checklist → briefly
check `vuln-intel.md` Section 3 for new dependencies only → write the lightweight report to
`security-reports/`. Do not perform attack testing or start listeners. If a suspected P0 is
found, explicitly recommend a full security audit.
