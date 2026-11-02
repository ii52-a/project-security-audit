# Risk assessment — alpha1.4

Severity, confidence, evidence status and coverage are separate fields.

| Severity | Meaning |
|---|---|
| P0 | Critical direct compromise or major data/authorization exposure |
| P1 | High impact with meaningful exploitation preconditions |
| P2 | Limited impact or constrained exploitation |
| P3 | Hardening advice without demonstrated direct exploitation |

Assess impact, reachability, preconditions and verified mitigations in the actual context.
Do not classify every outdated dependency as a vulnerability or every test credential as
production exposure. Confirmed disclosed production secrets require rotation.

Confidence: high = direct reproducible evidence or complete static path; medium = partial
path with stated assumptions; low = heuristic candidate. Status: confirmed, suspected,
not-reproduced, resolved. Not-reproduced does not reduce severity or halve deductions.
Resolution requires a fix plus targeted regression evidence, not absence from a new scan.

## Conclusion

1. Unresolved P0/P1: release blocked pending remediation/verified mitigation.
2. Missing coverage, failed/skipped checks or unverified hypotheses: manual review required.
3. Otherwise document remaining P2/P3 remediation and risk acceptance; never claim a security guarantee.
4. `releasable` is reserved by the machine contract for comprehensive, complete agreed scope,
   no limitations or unresolved checks/findings, with explicit redaction review.
Quick reports cannot declare unconditional release readiness.

## Optional score

Five dimensions: attack surface 25%, access control 30%, data protection 20%, supply
chain 15%, operations 10%. If used, assign 0–10 per dimension and explain evidence and
finding IDs behind every deduction; weighted total = sum(score * weight) / 10.
Do not score unexamined dimensions or substitute scores for release blockers. Keep score
out of quick reports. A number is an internal tracking aid, not calibrated assurance.
