# Recent Vulnerability Intelligence Workflow

Correlate what the project uses with what has recently been disclosed. Search for known
vulnerabilities in the project's stack and dependencies, verify affected versions, and
feed the results into the report and, when safe, into attack hypotheses. **Intelligence is
time-sensitive: the report MUST record the search date and sources.**

## 1. Input: component inventory (from Stage 1 and lock files)

Extract four categories. Every entry MUST carry an **exact version** from the lock file,
not a loose range from `package.json` or `requirements.txt`:

1. Runtime and framework: language version, web framework, template engine.
2. Infrastructure: nginx, database, Redis, MQ, object-storage SDK.
3. Critical third-party libraries: authentication (JWT/passport), parsing
   (YAML/XML/Fastjson), file processing (image/archive).
4. Containers and images: base image (`FROM` line), orchestration component versions.

If the component count exceeds 30, prioritize libraries in the first three categories that
directly process untrusted input or sit on a network boundary.

## 2. Automated audit (run first when network access is available)

```bash
npm audit --omit=dev                 # Node (reads the lock file)
pip-audit -r requirements.txt        # Python (install with: pip install pip-audit)
govulncheck ./...                    # Go
cargo audit                          # Rust
trivy fs <directory>                 # General, including images, if installed
composer audit                       # PHP
```

If a tool is unavailable or there is no network access, continue with Section 3. Note that
`npm audit` includes dev dependencies by default and inflates noise; always use
`--omit=dev`.

## 3. Web search workflow

For each critical component, search from precise to broad:

1. `<component> <major version> CVE <current year>` (prefer English for coverage).
2. `<component> security advisory` (prefer GitHub Security Advisories and vendor
   advisories).
3. For Chinese components, also search `<component> 漏洞 通报` (CNVD/CNNVD and vendor
   Chinese advisories).
4. Framework-level search: `<framework> vulnerability <current year-month>` to catch
   supply-chain incidents and embedded components.

Source precedence: vendor advisory ≥ GitHub Advisory/NVD ≥ security-vendor analysis ≥
forum repost. Record the source URL and publication date for every item. The report's
"search date" MUST be the actual execution date, not an example date copied from this
document.

**In-the-wild bonus:** mark a CVE with `⚡` when it appears in the CISA KEV catalog or a
source states that a PoC or in-the-wild exploitation exists. Raise its severity accordingly
(see Section 5).

## 4. Impact verification (prevent "report every CVE")

For every candidate, answer three questions. If you cannot answer them, discard the item:

1. What is the **affected version range** (`>=x <y` in the advisory)?
2. Does the **actual project version** fall inside that range? Check the lock file
   version; mark `REVIEW REQUIRED` when the range is uncertain.
3. Does the project satisfy the **triggering condition**? For example, if the vulnerable
   code is an XML parser the project never uses for untrusted input, downgrade it to
   "theoretically affected".

## 5. Summary table (report section "Recent vulnerability intelligence")

```text
| CVE/ID | Component | Affected range | Project version | Affected | CVSS/severity | In the wild | Fixed version | Action |
|---|---|---|---|---|---|---|---|---|
| CVE-<year>-XXXXX | fastjson 1.2.x | < 1.2.83 | 1.2.76 | yes | 9.8 | ⚡ PoC exists | 1.2.83 | Upgrade immediately; disable the deserialization entry point before upgrading |
```

Severity mapping when merging into the main findings table: affected + in-the-wild `⚡` →
P0; affected + CVSS ≥ 9 → P0; affected → P1; theoretically affected (trigger not met) →
P3, recorded for awareness; review required → "manual review required", not in the main
table.

## 6. Link to attack testing

For an affected injection, deserialization, or RCE issue with a public PoC in Section 5:
if Stage 7 dynamic testing is running (authorization gate passed), add a
**non-destructive** version of the PoC as attack hypothesis `ATK-xx` and validate it within
the red lines. If a safe variant cannot be constructed (the PoC downloads payloads or
establishes persistence), perform static confirmation only and mark it `NOT TESTED`.

## 7. Offline degradation

Without network access, state: "This audit did not perform online intelligence checks;
vulnerability coverage ends at the auditor's knowledge cutoff." List known CVE candidates
for high-risk components from existing knowledge, explicitly marked
"from memory; version ranges require manual verification". Do not invent CVE IDs.
