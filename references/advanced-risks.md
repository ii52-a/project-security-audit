# Advanced Risk Review Checklist

Depth dimensions that the baseline checklists (`server-vulns.md` and `api-audit.md`) do
not cover. Review each section. A high-risk item marked ★ that has static suspicion MUST
enter the Stage 7 attack-hypothesis list (`attack-testing.md`, Section 2).

## 1. Cryptographic misuse

- Weak algorithms: MD5/SHA-1 for passwords or signature checks; DES/3DES/RC4; AES-ECB
  (identical plaintext blocks produce identical ciphertext and can be analyzed block by
  block).
- IV/nonce reuse: hard-coded IVs or the same nonce for every encryption. Under GCM,
  nonce reuse is equivalent to key disclosure. ★
- Weak randomness: `Math.random()`, `random.random()`, or `rand()` used for tokens,
  CAPTCHAs, order numbers, or reset links (predictable → session forgery or enumeration). ★
- Timing comparison: `==` or `equals` used to compare signatures, HMACs, or password
  digests. Use constant-time comparison (`crypto.timingSafeEqual`,
  `hmac.compare_digest`).
- Password hashing: unsalted or globally fixed salt; bcrypt cost below 10; custom schemes.
- JWT: accepting multiple algorithms selected by the header (algorithm confusion); missing
  `exp`/`nbf` validation; the same secret reused for another purpose.

## 2. Race conditions and concurrency defects

- TOCTOU: check-then-use sequences such as `exists()` then `open()`, read balance then
  debit, or check uniqueness then insert, without a lock. ★
- Double-spend/oversell: coupon claims, inventory decrements, and points transfers are
  read-modify-write rather than atomic (no `UPDATE ... WHERE stock > 0`, no optimistic
  version column). ★
- Missing idempotency: payment callbacks or MQ consumers that credit or ship twice on
  redelivery (no unique business constraint or deduplication table).
- Lock granularity: in-process locks or in-memory maps protecting shared resources in a
  distributed deployment (ineffective across instances).
- Long transactions holding a lock while making external calls (HTTP or messaging),
  widening the race window.

## 3. LLM and AI application risks

- System-prompt disclosure: internal rules, credentials, or internal endpoints in the
  system prompt that can be induced to leak. ★
- Prompt injection: direct injection (user input overrides instructions) and **indirect
  injection** (instructions hidden in RAG documents, uploaded files, web pages, or email
  and executed as instructions by the model). ★
- Excessive agency: model output directly triggers deletion, bulk messaging, payment, SQL,
  or other high-risk tools without human confirmation or an allowlist. ★ Verify only on
  mock tools, dry-run tools, or a disposable test tenant; never perform real deletion,
  bulk messaging, or payment.
- Unsanitized output execution: model-generated code passed to `eval`, generated SQL
  executed directly, or generated shell executed directly.
- Data exfiltration: user PII or internal documents sent to a third-party model API
  (compliance and disclosure risk).
- Resource exhaustion: no per-user token or call limit (cost-based DoS).
- RAG poisoning: ordinary users can write to the knowledge source and influence answers
  for all users.
- Agent tool scope: file, browser, or HTTP tools without path or network-range
  restrictions; injection then becomes SSRF or arbitrary file read.

## 4. GraphQL and BFF

- Introspection and field suggestions enabled in production (error messages reveal the
  schema).
- No query depth or complexity limit (a deeply nested query can exhaust the database).
- Missing field-level authorization: the type resolver authorizes only the top level;
  sensitive fields such as `user { email salary }` are readable by any authenticated
  user. ★
- Batching abuse: multiple mutations in one request bypass rate limits.

## 5. WebSocket and real-time channels

- Origin is not validated during the handshake (any page can connect) ★; messages have no
  authorization after the connection is established, so a client can subscribe to any
  `userId`/`roomId` event stream. ★
- No message-size or send-rate limit; broadcast messages contain sensitive fields that
  should not be delivered to that channel.
- Reconnect tickets remain valid for too long.

## 6. Microservice internal trust

- "Internal network is trusted" assumption: service-to-service calls have no
  authentication, so compromise of one instance permits lateral movement. ★
- Forgeable identity propagation: the gateway authenticates and forwards
  `X-User-Id` to the backend, which does not re-verify it; direct access to the backend
  port impersonates any user. ★
- MQ publish/consume operations have no authorization; any process that can connect to
  the queue can inject messages.
- Debug endpoints (pprof, metrics, actuator) bind to `0.0.0.0`.

## 7. Cloud and IAM

- Object-storage buckets are publicly readable or writable; pre-signed URLs have excessive
  lifetimes (more than one hour) and guessable paths.
- Over-privileged roles or policies: `Action: "*"`, `Resource: "*"`; compromise of one
  service can take over the account. ★
- Security groups or NACLs allow `0.0.0.0/0` to databases, Redis, MQ, or management ports.
- Function timeouts, memory, and concurrency are unlimited (billing abuse); event triggers
  do not validate their source.

## 8. Front-end deep risks

- `postMessage` listeners do not validate `event.origin` and execute operations on any
  message ★; senders post sensitive data to `*`.
- Tokens stored in `localStorage`/`sessionStorage` (stolen by any XSS; `HttpOnly` cookies
  are safer). ★
- `window.open` or external links without `rel="noopener"` (reverse tabnabbing).
- Source maps (`.map`) deployed to production; error reporting (Sentry and similar) sends
  full state or form values.
- Service Worker scope is too broad and cache-update strategy is missing (hijacked
  content persists).

## 9. Mobile (if applicable)

- Third-party keys in `strings.xml`, `Info.plist`, or packaged resources; logging enabled
  in release builds.
- `allowBackup="true"` or `debuggable="true"` in release configuration.
- Residual disabled TLS validation (`TrustAllCerts`, `NSAllowsArbitraryLoads`). ★
- Deeplinks or URL schemes that do not validate their source and can jump directly to
  payment confirmation or OAuth callback pages. ★

## 10. Supply-chain poisoning

- Typosquatting (dependency names one or two characters away from a popular package);
  same name from a different registry.
- Unreviewed `postinstall`/`preinstall` scripts (fetching and executing remote scripts).
- GitHub Actions: third-party actions not pinned to a commit hash; `pull_request_target`
  executing fork content; secrets exposed to fork PRs.
- Git hooks, husky, or `prepare` scripts downloading and executing external binaries.
- Private registries or proxies pointing to unknown domains; tokens committed in
  `.npmrc`/`pip.conf`.

## Output requirements

- For every section, state what was checked and the conclusion. Record a result even when
  no issue is found.
- For a suspected ★ item, write the evidence location and explicitly add
  `→ entered attack hypothesis ATK-xx` (the ID is assigned in Stage 7).
