# Secrets, Hard-Coded Credentials, and Hijacking Risks

## 1. Hard-coded secret scan

Run `python scripts/scan_secrets.py <directory>` (cross-platform; if Python is
unavailable, use `bash scripts/scan_secrets.sh <directory>`) to obtain candidates, then
confirm each candidate manually. Manually check patterns the scanner cannot detect:

- Passwords or tokens written to logs (`console.log(password)`,
  `logger.info(token)`).
- Internal IP addresses, internal hostnames, and API keys in front-end bundles or source
  (search for `192.168.`, `10.`, `internal.`, and `api-key`).
- Third-party SDK keys in mobile configuration (`AndroidManifest`, `Info.plist`).
- Package-manager and container configuration: `_authToken` in `.npmrc`, plaintext
  `password` in `.pypirc`, base64 `auth` in Docker `config.json`, and Kubernetes Secret
  manifests.
- Connection strings included in exception messages by error handling.

## 2. High-risk hard-coded patterns

Use these patterns when reviewing scanner output:

| Category | Typical pattern |
|---|---|
| Cloud access keys | `AKIA[A-Z0-9]{16}` (AWS), `LTAI` (Alibaba Cloud), `AKLT` (Volcengine) |
| Private-key material | `-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----` |
| Database connection strings | `mysql://user:pass@`, `postgres://`, `mongodb://`, `redis://` with a password |
| JWT/signing secrets | Literal values assigned to `secret`, `jwt_key`, or `signing_key` |
| Email/SMS credentials | `smtp` password, `Authorization: Basic`, Twilio/SendGrid keys |
| OAuth client secrets | Literal `client_secret` |
| Payment keys | WeChat Pay `mch_key`, Alipay private key, Stripe `sk_live_`/`sk_test_` |
| Weak default passwords | `password = "123456"`, `root/root`, `admin/admin`, default tokens |

**Classification rule:** a real value in source or configuration that points to a
production environment (production domain or live key) is P0. A placeholder for a test
environment is P2. A value that exists only in example documentation may be ignored but
SHOULD be noted.

## 3. Secret-management practices

- Check whether secrets use environment variables or a secret manager (Vault, KMS, cloud
  function environment variables), and whether `.env` is in `.gitignore`.
- Check whether `.env.example` exists and contains no real values.
- Inspect Git history:
  `git log --all --diff-filter=A -- '*.env' '*.pem' '*.key' '*.p12'` and, for suspected
  values, `git log -p -S '<secret fragment>'`. **A secret that was ever committed MUST be
  treated as compromised and rotated; deleting the file is not remediation.** Record it as
  P0/P1 in the report.
- Check whether keys have an expiration/rotation procedure and whether the same key is
  reused across environments.
- In front-end projects, check whether "environment variables" are bundled into the
  artifact. Variables prefixed with `NEXT_PUBLIC_` or `VITE_` are public; placing a secret
  in one is P0.

## 4. Password and credential security

- Check for plaintext passwords in configuration, logs, error messages, and database seed
  data (real user passwords in a seed file).
- Review password policy: minimum length, complexity, blocked common passwords, and forced
  password change for default accounts.
- Review service credentials used between internal systems: whether a shared "super"
  account is used and whether credentials are hard-coded.

## 5. Hijacking risks

- **Session hijacking.** Missing `HttpOnly`/`Secure` cookies (XSS can steal the session),
  tokens in URLs, and no session-ID rotation after login (session fixation).
- **Clickjacking.** Missing `X-Frame-Options` or CSP `frame-ancestors`, especially on
  administrative and payment pages.
- **DNS/CDN hijacking surface.** Missing HTTPS/HSTS (a login page on HTTP can be
  hijacked), third-party JavaScript (analytics, SDKs, CDNs) without `integrity` SRI or
  self-hosting, and internal service discovery through untrusted public resolvers.
- **Machine-in-the-middle.** Internal `http://` calls and disabled certificate validation
  (`rejectUnauthorized: false`, `verify=False`, `InsecureSkipVerify: true`). Each instance
  is P1.
- **Supply-chain hijacking.** Dependencies pinned by version and hash (lock file
  committed), `postinstall` scripts from unusual packages, and registries that are not
  official or trusted private mirrors.
- **Account hijacking.** Changing email or phone without verifying the old credential,
  low-entropy or long-lived password-reset tokens, and OAuth `redirect_uri` validation
  failures (an open redirect can leak authorization codes).
- **Open redirect.** `redirect(parameter)` without an allowlist (`next=`, `returnUrl=`),
  usable for phishing and OAuth code theft.

## 6. Report redaction and compromise handling

- Secrets in the report show at most four leading and four trailing characters, with
  `****` in between; `Authorization`, `Cookie`, password, and token values are
  `[REDACTED]`.
- Mask phone numbers, email addresses, national IDs, and bank cards. Preserve the subnet
  of internal addresses but remove hostnames.
- Keep unredacted evidence in a separate, access-controlled local directory. Do not
  commit it or place it on a shared drive; the report SHOULD reference only
  `evidence file ID + location`.
- For a committed secret: **rotate first, then clean history**. Deleting the file is not
  remediation. Record the rotation steps, owner, and deadline in the report.
- Add the report file to `.gitignore`; write reports to `security-reports/`, not the
  repository root.
