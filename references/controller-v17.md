# alpha1.7 guided controller

Local standard-library Python JSON API; not an installed MCP server. Call
`python scripts/audit_control.py request.json` or JSON on stdin with `-`.
`dispatch(request)` is the Python entry. Responses are `{ok,result}` or `{ok:false,error}`;
exit 0 means handled, not security passed. Exit 2 is input/IO/validation failure.

## Recommended loop

1. `start` with target, state outside target, depth=quick/low/high, optional risks.
2. `run_pending` executes up to max_checks (default3, max10) pending automated checks.
   It does not retry completed checks and does not infer network authorization.
   Set allow_network=true only under existing authorization. Network-blocked checks stay pending.
3. `next_action` returns the next task AND a ready request object. For reviews it includes
   a blocked/unsigned draft plus grounded context. Fill evidence, explicitly set completion
   and redaction review, then submit the returned request. Never submit empty placeholders.
4. `finding_draft` generates a suspected finding skeleton from candidate_id; reviewer still
   decides severity/confidence/confirmation and remediation. It never invents confirmation.
5. `write_evidence` generates H evidence JSON, SHA256 and record from h_id, items, summary,
   redaction_reviewed=true. `review_template` for high-evidence incorporates saved artifacts.
6. `finalize` with output base outside target and redaction_reviewed=true writes JSON/Markdown
   exclusively. Every report still requires manual review; no release approval is automated.

Use `describe` for fields; `profiles` for executable budgets. No arbitrary command or
dynamic attack is accepted. Existing review references and safety requirements still apply.

## Calls

All stateful actions require state. Paths should be absolute; state parent must exist.

| Action | Additional fields / behavior |
|---|---|
| start | target, depth, optional risks |
| inspect / plan | current scope/plan, full freshness verification |
| next_action | instruction, request skeleton, source context; verifies freshness |
| run_pending | max_checks=1..10, allow_network=false; checkpoint after each check |
| run_check | check_id, optional retry and allow_network booleans |
| skip_check | check_id, reason; remains unknown and visible |
| review_template | check_id; same grounded review form as next_action |
| finding_draft | candidate_id; returns source plus fields requiring review |
| write_evidence | h_id, items, summary, redaction_reviewed=true |
| record_review | check_id, review |
| file_inventory | offset>=0, limit=1..500 (100 default); snapshot file page, no rehash |
| progress | compact saved progress, explicitly freshness=not-rechecked |
| status | current content-verified progress, may cost substantial IO |
| refresh | rebuild after content changes, preserve risks, invalidate checks and H artifacts |
| finalize | output, redaction_reviewed=true |
| compare | previous/current validated report paths; no state required |

Read-only progress/file_inventory never assert current freshness. Before execution,
review submission and finalization the controller still verifies the content snapshot.
Batching amortizes this check; target files must not be edited during a batch.

## Three levels

Same numerical profiles as alpha1.6; configured in audit_profiles.py. These are audit
effort levels, not host-model reasoning settings. Overall time is a target, per-tool caps enforced.

| Setting | quick | comprehensive-low | comprehensive-high |
|---|---|---|---|
| Time target | 15 min | 180 min | 300 min |
| Secret file cap | 1 MiB | 2 MiB | 5 MiB |
| Secret/config timeout | 60 s | 180 s | 600 s |
| History commits / timeout | 20 / 30s | 200 / 60s | 1000 / 180s |
| History output cap | 5 MB | 20 MB | 50 MB |
| Dependency command timeout | 60 s | 120 s | 300 s |
| Adapter output cap | 10 MB | 25 MB | 60 MB |
| Manifest depth (root=0) | 2 | 4 | 8 |
| npm development dependencies | omitted | included | included |
| Review passes | 1 | 1 | 2 |
| Analysis scope | changed sensitive paths | identified interfaces/high-risk paths | critical boundaries, authorization matrix, alternative hypotheses |
| High gate | none | none | H1-H8 integrity and structure |

Controller executes no dynamic tests. Quick forbids them; low/high may have separately
authorized isolated validation. No filler attack count, silent downgrade or automatic retry.

## Findings, dependency results and resolution

Dependency execution is distinct from advisory severity. Low/moderate advisories generate
candidates too. Structured records retain tool, advisory_id, component, installed_version
when available and severity. Summary-only output becomes an explicit summary-requires-review
candidate; unknown versions/IDs are not invented. npm output ranges are affected ranges,
not assumed installed versions. Unsupported/inconsistent schemas remain unknown.
Go JSON is decoded as an event stream; cargo found/count/list must agree when present.

C-IDs are deterministic for a source occurrence in the audited snapshot, not guaranteed
stable across line-moving edits. History includes column; exact duplicate records deduplicate.
Triage dispositions must cover every C-ID exactly and include evidence:
- confirmed: linked finding_id with status confirmed.
- false-positive: reason in evidence; not silent suppression.
- manual-review: preserved in report candidates and unresolved_candidates.
- resolved: linked finding_id with status resolved AND retest with method, expected,
  observed, evidence (nonempty strings) and passed=true. This records reviewed retest evidence;
  the controller does not independently execute the test or prove remediation.

## Inventory-derived coverage

Coverage review submits reviewed_files (unique snapshot paths), interfaces (objects with
unique id, file from snapshot, reviewed boolean), and interface_inventory_complete=true.
The controller calculates reviewed/total counts; a supplied coverage object must match.
If interface count is below the heuristic estimate, provide estimate_difference_reason.
Estimates are fallible; this exception is explicit, not a claim that all routes were discovered.
Unknown interface totals keep review blocked. File review declarations still rely on evidence;
programmatic arithmetic cannot prove that the reviewer actually read a file.
Forms include the first100 file choices; use file_inventory to page larger inventories.

## High evidence

High records and H-specific item fields follow the evidence table in controller-v16.md.
write_evidence removes manual JSON-file/hash work but never supplies the observations.
Artifacts are UTF-8 JSON under the state directory, <=5MiB, content-addressed filenames.
The controller checks path, hash and matching items on record/finalize. Second-pass requires
target/alternative_hypothesis/observation records. Plain 'checked' is insufficient.
Standalone report/high-status validators validate shape only; no trusted artifact root.

## Boundaries and migration

New alpha1.7 state required; no silent migration. Earlier reports remain historical;
coverage input changes to inventory records, while exported count fields remain compatible.
State uses exclusive lock/atomic save. Content snapshots include SHA256+Git HEAD, exclude
configured trees/symlinks, and are capped at50k files/1GiB. .github/.gitlab are included;
.git alone is excluded. Avoid concurrent target edits; inspect stale locks before removal.

Python config parsing handles direct/subscript DEBUG assignments and block Compose environment
maps/lists including quoted keys. It remains a conservative subset, not full YAML/dataflow.
AST vulnerability analysis, automatic authorization reasoning and MCP transport remain deferred.
Python enhancements are not mirrored in legacy Bash. No claim of cross-platform/live-registry
validation without actually executing it. Reports and evidence must be redacted and private.
