# alpha1.5 validation

Date: 2026-11-02 (Asia/Shanghai). Local Windows, Python 3.12.10.

- 51 unit/integration tests passed (`python -m unittest discover -s tests -q`).
- audit_doctor: 36 required files; version/depth docs and rule names consistent;
  zero failures, zero warnings.
- Python compileall passed.
- JSON CLI profiles and describe smoke calls succeeded.

New controller tests cover three distinct immutable default profiles, state outside target,
exclusive locks, restart/resume, cached calls, snapshot invalidation, manifest depth,
network gating, skipped/unknown results, triage evidence, actual scanner parameter forwarding,
redaction, high evidence gates, and end-to-end quick/high report creation without overwrite.

This is a local CLI/Python API release. No MCP server installation, host model setting
change, live registry/CVE query or business-project dynamic attack was performed.
Cross-platform CI is configured but was not executed here. Timeout/output caps are
implemented; not every OS process-tree failure mode has been integration tested.

Known limits: metadata snapshots can miss timestamp-preserving changes; excluded trees
are not tracked; manifest discovery is bounded; task reviews still require model judgment;
triage validation is check-level rather than proof of every candidate's disposition;
reports always require manual review. State/free-text evidence must be kept private and
redacted. See references/controller.md for complete boundaries and migration behavior.

alpha1.4 results remain separately recorded in VALIDATION.md.
