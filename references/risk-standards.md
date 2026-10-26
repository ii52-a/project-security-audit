# Project Risk and Security Assessment Standard

## 1. Severity classification (P0–P3)

| Severity | Criteria | Handling requirement |
|---|---|---|
| P0 Critical | Exploitable without special conditions and directly causes data disclosure, authorization bypass, or system compromise | Fix immediately; must be zero before release |
| P1 High | Exploitable with preconditions (authentication or specific configuration) but reliable; or large-scale sensitive-data exposure | Fix before release; tolerate for no more than 7 days |
| P2 Medium | Limited exploitation conditions or scope, or requires an attacker close to the system | Schedule within the next iteration (30 days) |
| P3 Low | Hardening recommendation with no direct risk | Continuous improvement |

**Severity modifiers** (the same issue may move up or down with context):

- Production credentials or real user data → raise one level. Test environment only →
  lower one level.
- Automated exploitation is feasible (a scanner can directly attack it) → raise one level.
- A real mitigation exists (for example, a WAF or network isolation) → lower at most one
  level, and state the mitigation assumption in the report.

**Dynamic-validation rules** (apply after Stage 7):

- **Reproduced dynamically** → mark `[VERIFIED]`; keep or raise the severity. **Do not
  downgrade based on a speculative mitigation.** A mitigation counts only if it is real
  and the attack actually failed to bypass it.
- **Not reproduced dynamically** (the attack ran but did not succeed) → downgrade the
  static severity by at most half a level and mark `NOT REPRODUCED (ATK-xx)`. Downgrade
  only if the attack actually covered the relevant path and the failure is not explained by
  an environment difference. Do not drop a full level merely because "the exploit did not
  work".
- **Not verifiable** (environment would not start, real third-party credentials required,
  and similar) → keep the static severity, mark `NOT VERIFIED`, and list it under
  "manual review required".

## 2. Five-dimension scoring (each 0–10; weighted total 100)

| Dimension | Weight | Scoring focus |
|---|---:|---|
| Attack-surface control | 25% | Minimal exposed ports and services; isolated administrative interfaces; documentation and debug endpoints disabled; unused dependencies and code removed |
| Authentication and access control | 30% | Password storage and policy; session management; complete authorization coverage (no unprotected endpoint); object-level authorization |
| Data protection | 20% | Key management; encryption in transit; sensitive-data redaction and log hygiene; backup and deletion policy |
| Dependency and supply chain | 15% | Known CVE count and severity; dependency-update process; lock files and source trustworthiness |
| Operations and incident response | 10% | Logging and alerting; error handling that does not disclose information; rollback, on-call contact, and security-update process |

**Per-dimension reference:** 0–2 = P0 present with no mitigation; 3–4 = P0 present with
partial mitigation, or multiple P1; 5–6 = no P0 and one or two P1; 7–8 = P2 only; 9–10 =
only isolated P3.

**Deduction calibration** (start at 10, subtract within the affected dimension, floor at 0;
use this to reduce drift between auditors):

| Finding | Deduction from the affected dimension |
|---|---:|
| P0, unmitigated | 4–6 |
| P0, with a real, verified mitigation | 2–3 |
| P1 | 1–2 |
| P2 | 0.5 |
| P3 | 0.1 |

Accumulate deductions within a dimension. The "Score breakdown" section MUST list the
finding ID for every deduction, not only a total. This table is a calibration aid, not an
exact formula; the final score MUST be explainable from the evidence.

**Score bands:** ≥85 A; 70–84 B; 50–69 C; <50 D. A/B/C/D indicate only the score band and
do not by themselves determine release status; the hard gates in Section 4 also apply.

## 3. Project risk dimensions (business risk beyond vulnerabilities)

Assess each item and include it in the report:

- **Data risk.** What sensitive data is collected (national ID, phone number, payment
  data)? Is collection minimized? Is it stored in plaintext? Does a deletion request
  actually delete it?
- **Compliance risk.** Are the password policy, log retention, and third-party SDK data
  sharing documented? For China-facing services, consider MLPS (Cybersecurity Classified
  Protection) and PIPL (Personal Information Protection Law) obligations. Provide
  indicative guidance only; do not make legal conclusions.
- **Availability risk.** Single points of failure (one database, one instance, one
  third-party API); endpoints that can be abused when no cache exists; no backups, or
  backups never tested for restore.
- **Process risk.** Whether releases bypass testing; how production and development
  configuration are separated; who has production access and whether it is audited.
- **Human-factor risk.** Traces of keys circulating in chat, tickets, or documents;
  internal sensitive information in code comments (internal topology, default accounts).

## 4. Overall conclusion

**Evaluate in this order and stop at the first match:**

1. **Not releasable** (hard red line, takes precedence over every other conclusion):
   three or more P0 findings, a credential that was disclosed and must be rotated, or a
   completely missing authentication system.
2. **Releasable after remediation:** P0/P1 findings exist, but the remediation path is
   clear and the estimated effort is small (≤3 days).
3. **Releasable:** no P0, no unmitigated P1, and total score ≥85.

If a project matches more than one condition, use the most restrictive conclusion and state
which condition was matched. Do not let a high total score override a hard red line.

## 5. Finding write-up requirements

Every finding MUST contain all five elements:

```text
[P1] Horizontal privilege escalation — any user's orders can be read
Location: src/routes/orders.ts:42
Issue: findById(orderId) does not verify order ownership
Exploitation: log in as any account, then GET /api/orders/<another user's order ID>
Remediation: add userId = currentUser to the query; add an integration test for this route
```

For a dynamically verified finding, use the "endpoint + attack record" format. The attack
ID MUST map to the evidence row in the report's dynamic-test section:

```text
[P0][VERIFIED] SQL injection — time-based blind injection in the items endpoint
Location: GET /api/items?id= (source: src/routes/items.ts:31, string concatenation)
Attack record: ATK-05 — payload `id=1;SELECT SLEEP(2)--` increased response time from 0.1s to 2.4s (reproduced twice)
Exploitation: time-based blind injection can extract the entire database byte by byte
Remediation: use parameterized queries and a numeric allowlist for id; add a blind-injection regression test
```

Remediation MUST be specific to the code or configuration (which file to change, which
validation to add). Do not write generic advice such as "strengthen access control".

## 6. Report evidence redaction

The report is itself a sensitive artifact. Apply these rules before writing it:

- Secrets and credentials: retain at most the first and last four characters with `****`
  in between; a complete value MUST NOT appear in the report.
- `Authorization`, `Cookie`, `Set-Cookie`, password, token, and secret fields: replace the
  value with `[REDACTED]`.
- Phone numbers, email addresses, national IDs, and bank cards: mask while preserving the
  identifiable format (for example `138****1234`, `a***@example.com`).
- Internal addresses: preserve the subnet but remove specific hostnames and accounts.
- Keep unredacted evidence separately, with least-privilege directory permissions. Do not
  commit it to Git or place it on a shared drive. Appendix B MUST state the storage
  location and access control.

If evidence cannot be redacted but must be retained, move it out of the report and replace
it with `evidence file ID + location`; the report body references only the ID.
