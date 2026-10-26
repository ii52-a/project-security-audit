# Targeted Review Prompts (Second Pass)

After the first full scan, use these category prompts for a second pass on high-risk
modules. Apply each prompt to the actual code context. For every question, produce exactly
one of: **Confirmed safe**, **Confirmed issue**, or **Cannot determine**. Put "Cannot
determine" items under "manual review required". Do not skip a question.

## Universal review prompt (any file)

> Read the following files line by line, assuming the attacker controls every external
> input: HTTP parameters, headers, file contents, message-queue messages, third-party API
> responses, and any source other than environment variables. For every path where data
> flows from an entry point to a dangerous operation, write: entry point → every
> transformation along the path → sink. If no reachable dangerous path exists, state
> explicitly: "no reachable sink".

## Category 1: Injection and command execution

> In these files, find every call site that reaches SQL, a shell command, `eval` or dynamic
> code, a template engine, or deserialization. For each call site, answer: (a) Which parts
> of the arguments are user-controlled? (b) What protection exists (parameter binding,
> allowlist, escaping), and can it be bypassed (double decoding, encoding differences,
> field-name concatenation)? (c) If injection succeeds, what can the attacker obtain
> (arbitrary read from the same database? RCE?). Mark suspicious rather than dismiss.

## Category 2: Authentication and sessions

> Trace one complete login flow: how the password is verified, how the session or token is
> generated and signed, where it is stored, how it is validated on each request, and how it
> is invalidated. Answer each question: Can the token be forged (secret source, fixed
> algorithm)? Does an old token still work after logout or password change? How long is
> "remember me" valid, and can a stolen token be reused long-term? Does the login-failure
> message help enumerate accounts? Is there an endpoint that authenticates by cookie but is
> vulnerable to CSRF?

## Category 3: Authorization (IDOR)

> List every endpoint of the form "fetch/update/delete a resource by ID". For each one,
> locate the data query and confirm whether the `WHERE` clause binds the owner or role in
> addition to the ID. If it does not, classify it as a horizontal-privilege-escalation
> candidate and write the exploitation steps. For administrative endpoints, produce a
> separate table: path + authentication middleware name + what the middleware actually
> validates.

## Category 4: Secrets and sensitive data

> Assume the repository will become public. For each file, answer: Does it contain anything
> that would cause direct loss if published (keys, passwords, internal addresses, customer
> data, internal hostnames)? Also answer: If an attacker obtained any one of these secrets,
> which system could they enter, and what impact could they cause? Provide rotation steps
> for every discovered secret.

## Category 5: Files and uploads

> Trace the full lifecycle of an uploaded file: how the front end sends it → how the server
> validates it (extension? MIME? magic bytes?) → where it is stored and under what name →
> how it is later accessed or executed. For each stage, describe bypasses: double
> extensions, case variation, semicolon truncation, Content-Type spoofing, polyglot images,
> and archive path traversal. Are download/read endpoints immune to `../`, absolute paths,
> and URL encoding (`%2e%2e`)?

## Category 6: SSRF and outbound requests

> Find every place where the server initiates an HTTP request. For each one: Which parts of
> the URL are user-controlled? Are protocols (`file://`, `gopher://`) and destinations
> (internal IPs, cloud metadata `169.254.169.254`) restricted? Are redirects followed (a
> redirect can bypass initial validation)? Is the resolved IP re-checked after DNS
> resolution (rebinding)?

## Category 7: Business-logic abuse

> Review from the perspective of a user trying to exploit promotions or obtain goods for
> free: Is there human-verification on registration? Can coupons or referral rewards be
> farmed? Is the payment amount supplied by the client or computed by the server? Can
> concurrent requests to the same coupon oversell it (idempotency and locking)? Can SMS or
> email endpoints be used as a bombing service? Do trial or refund flows contain
> "refund-before-receipt" defects?

## Category 8: Dependencies and supply chain

> For each package in the dependency manifest, answer: Does the version fall inside a known
> CVE range (verify with npm audit/pip-audit when online; otherwise mark it as
> knowledge-based)? Is the package still maintained? Does the project use only a small part
> of it (could the standard library replace it and shrink the supply chain)? Do build
> scripts and `postinstall` perform suspicious network activity?

## Category 9: Deployment and configuration review

> Review deployment configuration from the perspective of an attacker who just obtained a
> shell on the server: Which user does the container run as, and which mounts can it read?
> Where is the database port bound? Where are backups stored, and who can download them?
> What sensitive information is currently written to logs? After this host is compromised,
> where can the attacker move laterally (other service credentials, shared networks)?
> Write each answer as an impact chain.

## Category 10: Cryptography and randomness

> Find every call site for encryption, hashing, signing, and random-number generation. For
> each one, answer: What algorithm and mode are used (MD5/SHA-1/ECB/reused IV = suspicious
> immediately)? Where do keys and salts come from, and how often are they rotated? Are
> signatures and digests compared in constant time or with `==`? Is the randomness source
> for tokens, CAPTCHAs, and reset links a CSPRNG or `Math.random`/`random.random`? Describe
> concrete scenarios for what a predictable token can forge.

## Category 11: Race conditions and idempotency

> Find every "read then write" path that changes money, inventory, or entitlements. For each
> one, answer: Is the read-modify-write atomic (optimistic lock, conditional UPDATE, or
> unique constraint)? Does redelivery of the same request (payment callback, MQ retry)
> apply twice, and where is the idempotency key? In a distributed deployment, is an
> in-process lock still protecting a shared resource? Mark every non-atomic point with
> "can 15 concurrent requests oversell?" — that is the target for Stage 7 race testing.

## Category 12: LLM and agent applications

> For every model invocation point, answer: Does the system prompt contain secrets that can
> be induced to leak (internal rules, credentials, internal endpoints)? Are user input and
> retrieved documents concatenated into the same instruction (indirect-injection surface)?
> Where does model output go — `eval`, SQL, shell, or payment tools — and is it sanitized
> and allow-listed? Do high-risk tools (deletion, bulk messaging, payment) require human
> confirmation? What is the per-user token or call limit? Can ordinary users write to the
> knowledge source? For every "yes", write the concrete consequence of injection.
