# project-security-audit

`security-audit` is a security-audit skill for AI agents: static review, authorized
AI-driven attack validation, vulnerability-intelligence correlation, risk scoring, and an
actionable remediation report.

Current version: **alpha1.2**

## Language layout

- **English is authoritative for execution.** `SKILL.md`, `references/*.md`, this README,
  and `CHANGELOG.md` are the machine-facing specification.
- **Chinese is the human-facing manual.** The synchronized Chinese reading version lives in
  `.chinese/`. Agents do not need to read it for execution; it is provided for Chinese
  readers who want the narrative in Chinese.
- If the two versions disagree, the English files prevail.

## Use cases

- Pre-release security review of a project
- First-pass security reconnaissance when taking over an unfamiliar codebase
- Secret and hard-coded credential checks, API authorization review, dependency CVE review,
  and deployment configuration review
- Pre-release quick self-review (A-track), in-iteration gates (B-track), and monthly deep
  review (C-track)
- Producing a reproducible security report instead of scattered advice

## Repository layout

```text
.
├── SKILL.md                     # authoritative workflow and report contract (English)
├── VERSION
├── CHANGELOG.md
├── README.md
├── references/                  # English execution references
│   ├── server-vulns.md
│   ├── api-audit.md
│   ├── secrets-hijack.md
│   ├── advanced-risks.md
│   ├── vuln-intel.md
│   ├── attack-testing.md
│   ├── risk-standards.md
│   ├── structure-optimization.md
│   ├── performance.md
│   ├── audit-prompts.md
│   └── self-review.md
├── scripts/
│   ├── scan_secrets.py          # cross-platform scanner (preferred)
│   ├── self_check.py            # cross-platform quick check (preferred; --strict)
│   ├── scan_secrets.sh          # bash fallback
│   └── self_check.sh            # bash fallback
├── tests/
│   └── test_smoke.py
├── .github/workflows/ci.yml
└── .chinese/                    # Chinese human manual; not needed by agents
    ├── README.md
    ├── SKILL.md
    ├── CHANGELOG.md
    └── references/
```

The `.chinese/` directory is intentionally hidden from the normal reading path. It is a
human manual, not a second execution specification. Do not load it as context for an audit
unless the user explicitly asks for the Chinese version.

## Quick start

```bash
# Pre-release check; non-zero exit on FAIL, suitable for CI
python scripts/self_check.py <project-dir> --strict

# Secret scan with JSON output
python scripts/scan_secrets.py <project-dir> --json

# Regression tests after changing rules or scripts
python -m unittest discover -s tests -v
```

The Python tools run on Windows, Linux, and macOS. The bash tools require Linux, macOS, or
Git Bash. On Windows, the built-in `bash.exe` may be a WSL launcher without a distribution;
do not assume it is usable.

## Requirements

- Python 3.9+ for static review and quick checks
- bash 4+, `grep`, and `find` only when using the bash fallbacks
- `curl` for dynamic testing; command templates use bash syntax, so use Git Bash on Windows
  or translate them to equivalent PowerShell
- Optional dependency-audit tools: `npm`, `pip-audit`, `govulncheck`, `cargo`, `composer`
- Dynamic testing is permitted only in a user-authorized local or test environment

## Safety boundaries

- Static review does not modify or delete project files.
- Dynamic attack testing requires explicit authorization, environment isolation, and red-line
  compliance.
- Destructive payloads, denial-of-service testing, third-party attacks, and access to real
  user data are prohibited.
- LLM tool-abuse tests may use only mock tools, dry-run tools, or a disposable tenant; real
  deletion, bulk messaging, and payment are prohibited.
- Reports are written to `security-reports/` and redacted; raw evidence is never committed.

## Versions

- **alpha1.2** — English-first migration. The English `SKILL.md` and `references/` are the
  authoritative execution specification; the Chinese manual is synchronized under
  `.chinese/`. No changes to detection behavior.
- **alpha1.1** — Safety and consistency fixes; cross-platform Python tools; regression tests
  and CI; report redaction, coverage boundaries, and appendix contracts.
- **alpha1.0** — Initial snapshot: ten-stage workflow, 11 reference files, two bash scripts,
  report template, and A/B/C self-review cadence.

## License

No license has been declared. Add one before redistribution if required by your
organization.
