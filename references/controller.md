# Controller and depth contracts — alpha1.5

Use `python scripts/audit_control.py request.json` or pipe one JSON object to stdin
with `python scripts/audit_control.py -`. Every call returns `{ok,result}` or
`{ok:false,error}`. Exit 0 means the request was handled, NOT that security checks passed;
exit 2 means request/IO/validation failure. Inspect `execution` and `assessment` separately.
The callable Python entry point is `audit_control.dispatch(request)`.

This is a local CLI/API tool interface, not an installed MCP server. `describe` lists
actions and parameters; `profiles` returns exact executable defaults. No additional
package installation or network service is required. All file paths should be absolute.

## Workflow

1. `start`: target, state (outside target), depth (quick/low/high), optional risks.
2. `next_action`: consume the returned check ID, tool/review type, reference and instruction.
3. `run_check`: check_id; dependency tools require allow_network=true. Existing user
   authorization remains valid; this parameter records it, not a new permission dialog.
4. If a tool cannot be executed, `skip_check` with a redacted reason. Skips remain limitations.
5. `record_review`: check_id and review with status, evidence and redaction_reviewed=true.
6. `status` supports resuming. `refresh` invalidates ALL checks if snapshot changed.
7. `finalize`: output base path outside target and redaction_reviewed=true; creates
   .json and .md exclusively. Always produces manual-review-required, never release approval.
8. `compare`: previous/current validated JSON reports.

Example request:
```json
{"action":"start","target":"D:/projects/demo","state":"D:/audits/demo-state.json","depth":"high","risks":["payment"]}
```
Then `{"action":"next_action","state":"D:/audits/demo-state.json"}`.

## Three depth levels

These are audit effort levels, not API model reasoning-effort settings. No model switch
is performed. Parameters are maintained in scripts/audit_profiles.py, exposed by profiles.

| Setting | quick | comprehensive-low | comprehensive-high |
|---|---|---|---|
| Planning time target | 15 min | 180 min | 300 min |
| Secret scan file cap | 1 MiB | 2 MiB | 5 MiB |
| Secret/config timeout | 60 s | 180 s | 600 s |
| History commit cap | 20 | 200 | 1000 |
| History timeout | 30 s | 60 s | 180 s |
| History output cap | 5 MB | 20 MB | 50 MB |
| Dependency timeout per command | 60 s | 120 s | 300 s |
| Adapter output cap | 10 MB | 25 MB | 60 MB |
| Manifest discovery max depth (root=0) | 2 | 4 | 8 |
| Review passes | 1 | 1 | 2 |
| Interface review | changed/new | all identified | all identified + authorization matrix |
| Manual analysis | changed security paths | boundary-to-sensitive-operation tracing | critical boundary tracing + alternative-hypothesis second pass |
| High evidence gate | none | none | H1-H8 with evidence/reasoned N/A |
| Dynamic testing policy | forbidden | separately authorized, risk-prioritized | separately authorized, applicable critical hypotheses |

The controller executes no dynamic attacks at any level. External dynamic evidence must
be reported separately; finalize explicitly states dynamic testing was not executed by
the controller. Time targets are advisory, per-tool caps are enforced. No filler attack
counts. No silent downgrade. Scan traversal includes first-party working-tree text under
the scanner's exclusion rules; manifest depth does not limit secret scan directory depth.
No automatic retries. retry=true explicitly reruns a check and invalidates triage.

## Evidence and state

Tool results: execution=complete/incomplete/error/skipped; assessment=no-candidates/
candidates/unknown. These dimensions must not be collapsed. A completed tool can discover
vulnerabilities; an incomplete tool may still contain valid candidates.

Reviews: status=done/blocked/not-applicable plus nonempty evidence. Coverage, triage and
high-evidence cannot be N/A. Coverage needs files/interfaces reviewed/total counts; unknown
totals remain blocked. Triage requires dispositions keyed by every candidate-bearing check
ID: `{status: confirmed|false-positive|manual-review, evidence: ...}`. Evidence must account
for each candidate; code currently verifies check-level presence, not candidate-level truth.
Optional findings use the existing report contract. High review includes high_only H1-H8.

State uses atomic replacement and an exclusive lock. Only one writer per state is allowed.
After a crash, a leftover .lock must be inspected against its PID before manual removal;
the controller never silently breaks a lock. State is sensitive: keep it access-controlled
and outside version control. Tool snippets are redacted, but paths/free-text reviews still
need review. State files are trusted local records, not signed tamper-proof evidence.

Snapshot uses path/size/mtime_ns plus Git HEAD, capped at 50k files. Excluded directories
and symlinks are not tracked. It is a change detector, NOT a cryptographic content snapshot;
same-size/mtime-preserving edits and excluded-tree changes can escape detection. Narrow
scope or start a new audit when that risk matters. refresh conservatively repeats all
checks; dependency-aware incremental invalidation is deferred.

Current adapters retain legacy dependency/configuration coverage and limitations. Exact
package versions and framework authorization paths still require specialist review.
MCP transport, AST extraction and automatic exploit orchestration are deferred.
