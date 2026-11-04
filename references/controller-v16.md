# Controller contract — alpha1.6

Use `python scripts/audit_control.py request.json` or send one JSON object on stdin
with `python scripts/audit_control.py -`. Python callers use `dispatch(request)`.
Responses are `{ok:true,result:...}` or `{ok:false,error:...}`. Exit 0 means handled,
not security passed; exit 2 means invalid input/IO/validation failure. This is a local
CLI/API, not an installed MCP server. `describe` lists input fields and high evidence fields.

## Workflow

All paths should be absolute. State parent must already exist and be outside target.

| Action | Fields beyond action |
|---|---|
| profiles / describe | none |
| start | target, state, depth=quick/low/high, optional risks array |
| inspect / plan / next_action / status | state |
| run_check | state, check_id; allow_network=true for dependencies; optional retry boolean |
| skip_check | state, check_id, redacted reason; skip remains unknown |
| record_review | state, check_id, review object |
| refresh | state; invalidates changed scope and preserves declared risk focus |
| finalize | state, output base outside target, redaction_reviewed=true |
| compare | previous/current validated JSON report paths |

Follow start -> next_action -> run_check/record_review -> finalize. No arbitrary shell
command or dynamic attack is accepted. Reuse existing authorization; allow_network records
it. Existing completed checks are cached; retry=true explicitly reruns and invalidates triage.

## Three effort levels

Defined in audit_profiles.py and exposed by profiles. These are audit budgets, not model
reasoning settings. Targets are advisory; individual tool caps are enforced.

| Setting | quick | comprehensive-low | comprehensive-high |
|---|---|---|---|
| Planning target | 15 min | 180 min | 300 min |
| Secret file cap | 1 MiB | 2 MiB | 5 MiB |
| Secret/config timeout | 60 s | 180 s | 600 s |
| History commits | 20 | 200 | 1000 |
| History timeout | 30 s | 60 s | 180 s |
| History output cap | 5 MB | 20 MB | 50 MB |
| Dependency command timeout | 60 s | 120 s | 300 s |
| Adapter output cap | 10 MB | 25 MB | 60 MB |
| Manifest depth, root=0 | 2 | 4 | 8 |
| Review passes | 1 | 1 | 2 |
| Interfaces | changed/new | all identified | all identified + authorization matrix |
| Analysis | changed sensitive paths | high-risk boundary-to-sink tracing | critical boundaries + alternative-hypothesis review |
| High gate | none | none | H1-H8 artifacts |

Quick forbids dynamic testing; low/high permit separately authorized isolated validation.
The controller executes none. No filler attack counts, automatic retries or silent downgrades.
Secret traversal uses scanner exclusions, independently of manifest depth. Direct-script
defaults are independent of profiles. High does not automatically scan vendor/build output.

## Results, review and candidates

execution=complete/incomplete/error/skipped; assessment=candidates/no-candidates/unknown.
Secret coverage=complete/partial; history is bounded. Skipped content or zero files means
partial coverage, even if execution completed. Report includes skipped paths and reasons.

Review: status=done/blocked/not-applicable, nonempty redacted evidence, redaction_reviewed=true.
Optional findings follow report-format.md. Coverage requires valid files/interfaces
reviewed/total counts; unknown totals remain blocked. Coverage/triage/high-evidence cannot be N/A.

Every automated candidate has a stable C-ID. Triage dispositions must contain exactly all
candidate IDs. Each disposition needs status=confirmed/false-positive/manual-review and
evidence. Confirmed also requires finding_id linked to a confirmed finding in the current
or another review. manual-review remains in candidates/unresolved_candidates in JSON and
Markdown. Finalize rechecks all links; candidates cannot disappear through an empty findings list.

Second-pass requires analysis items with target, alternative_hypothesis and observation.
Plain text "checked" cannot satisfy this gate.

## High evidence

Each H record: `{status:"done", evidence:{artifact,sha256,summary,items}}`, or
`{status:"n/a",reason:"..."}`. H6/H8 always apply. Artifact is a UTF-8 JSON file under
the state directory, max 5MiB, containing `{"Hn":[...items...]}`. Controller verifies
path containment, SHA256 and matching item contents on record and finalize. Standalone
report/high-status validators check shape only, because they have no trusted artifact root.

Each item requires nonempty strings:

| Item | Fields |
|---|---|
| H1 | interface, caller, object_check, output, rate_limit |
| H2 | boundary, identity, trust_check |
| H3 | hypothesis, method, outcome |
| H4 | component, version, advisory_check |
| H5 | target, alternative_hypothesis, observation |
| H6 | scope, coverage, evidence_index |
| H7 | configuration, check, observation |
| H8 | finding_ids, conclusion_check, remediation_check |

Use concrete source locations and observations. Hashes bind an artifact, not the truth of
its claims. Redact artifacts before persistence; evidence still needs substantive review.

## State, boundaries and migration

Atomic save and exclusive lock permit one writer. Inspect leftover lock PID after a crash
before removal. State is trusted private data, not signed evidence; keep it out of Git.
Content snapshots use SHA256 and Git HEAD; same-size/mtime-preserving edits are detected.
Excluded trees/symlinks remain untracked. Limit is 50k files and 1GiB; narrow scope if exceeded.
Snapshots are not atomic filesystem snapshots: avoid concurrent target edits. Refresh
invalidates all checks. Content hashing increases IO versus alpha1.5.

Finalize exclusively creates JSON/Markdown, preserves candidates/omissions and always says
manual review required. It does not grant release approval. Dependency schemas fail closed.
Python debug uses AST. Compose supports block environment maps/lists and warns on complex
forms; this is not a general YAML parser. Secret scanning remains heuristic.

Start a new alpha1.6 state; old states are rejected. Migrate per-check dispositions to C-IDs,
string high evidence to artifacts, and second-pass text to analysis records. Old reports
remain historical evidence; old high reports require migration before new validation.
MCP, general vulnerability AST/dataflow analysis and automatic exploitation remain deferred.
