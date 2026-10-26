# Server and Runtime Vulnerability Checklist

Work through each category. For every finding, record the location and the evidence.
Review server-side code and deployment configuration before front-end code.

## 1. Injection

- **SQL injection.** Search for string-concatenated SQL: `+ sql`, `f"SELECT`, `"SELECT " +`,
  template literals embedded in queries, and `query(` receiving a concatenated string.
  Treat ORM `raw()` / `queryRaw()` calls the same way: verify that parameters are bound.
  Check whether sort and filter field names are allow-listed; `ORDER BY ${userInput}` is a
  high-frequency vulnerability.
- **Command injection.** Check whether arguments to `exec`, `spawn` with `shell: true`,
  `os.system`, `subprocess(..., shell=True)`, and `Runtime.exec` contain user input.
- **Code and template injection.** Check `eval`, `Function()`, `pickle.loads`,
  `yaml.load` (non-safe), and SSTI sinks where user input reaches
  `render_template_string` or `Template`.
- **Path traversal.** When user input is joined into a file path, verify that `../` is
  rejected and that the resolved path remains inside the allowed directory. Cover upload,
  download, read, delete, and archive extraction (zip-slip) paths.
- **Deserialization.** Java (`ObjectInputStream`, old Fastjson/SnakeYAML), Python pickle,
  Node `node-serialize`, and PHP `unserialize`.
- **XSS.** Check `innerHTML`, `dangerouslySetInnerHTML`, and `v-html` receiving user data;
  verify rich-text sanitization (for example DOMPurify) and server-side template escaping.
- **XXE.** Verify that XML parsers disable external entities
  (`FEATURE_SECURE_PROCESSING`, `resolve-entities=false`).
- **LDAP, XPath, and NoSQL injection.** Check `$where` and `$ne` receiving user-controlled
  Mongo query objects.

## 2. Authentication and sessions

- **Password storage.** Reject plaintext, MD5, and SHA-1. Use bcrypt, argon2, or scrypt.
- **Sessions and tokens.** Verify JWT signature and algorithm validation (prevent
  `alg:none` and RS256/HS256 confusion), secret strength, session-ID rotation after login,
  and cookie attributes `HttpOnly`, `Secure`, and `SameSite`.
- **Login abuse.** Check for failed-login lockout, CAPTCHA, or rate limiting.
- **Password reset.** Verify that tokens are unpredictable, single-use, and time-bound,
  and that the reset flow cannot change another user's password.
- **Multi-tenant and API-key concerns.** Check "remember me", API-key rotation, and whether
  tokens are invalidated after logout (denylist or short lifetime).

## 3. Authorization and access control (server side)

- Verify that every endpoint re-checks authorization on the server. Hiding a UI element is
  not authorization.
- **IDOR.** For endpoints such as `/api/users/123/orders`, verify that `123` is checked
  against the current user's ownership.
- Verify that administrative endpoints are isolated from business endpoints and protected
  by a dedicated authorization middleware.
- Check unauthenticated access to debug, health, Actuator, Swagger, Druid, and `/.git`
  endpoints (`/debug`, `/actuator/env`, `/druid`, `/swagger`, `/.git`).

## 4. File handling

- **Upload.** Verify content-based type validation (magic bytes), not only extension or
  MIME type; enforce a size limit; store files outside the web root with randomized names;
  and prevent overwrite of existing files.
- **Download.** Check for arbitrary file read through path traversal or direct absolute
  paths.
- Check image-processing libraries (ImageMagick, Pillow, Sharp) for known CVEs.

## 5. SSRF, CSRF, and hijacking

- **SSRF.** Check whether server-initiated HTTP requests use user-controlled URLs; block
  internal ranges (127.0.0.1, 10/8, 172.16/12, 192.168/16, 169.254.169.254 cloud metadata);
  block redirect-based bypasses and DNS rebinding.
- **CSRF.** Verify that state-changing endpoints validate a CSRF token or rely on
  `SameSite`; verify that JSON APIs validate `Content-Type`.
- **Clickjacking.** Verify `X-Frame-Options: DENY` or CSP `frame-ancestors`.
- **Machine-in-the-middle and downgrade.** Verify HTTPS enforcement (HSTS), absence of
  internal HTTP downgrades, `wss` for WebSockets, and SRI (`integrity`) on external CDN or
  script references.

## 6. Security headers and browser protections

Check response headers in nginx configuration or framework middleware:

- `Content-Security-Policy` (flag `unsafe-inline`, `unsafe-eval`, and `*`)
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options`
- `Strict-Transport-Security`
- `Referrer-Policy`
- Error pages MUST NOT disclose stack traces, SQL, or framework versions. Production MUST
  disable debug mode (`DEBUG=True`, `app.run(debug=True)`, Spring devtools).

## 7. Deployment and infrastructure configuration

- **Docker.** Check for root execution, `docker.sock` mounts, host networking, secrets in
  image layers (`ENV`/Dockerfile), and outdated base images.
- **docker-compose.** Check database ports exposed publicly and default passwords
  (`postgres/postgres`, `root/root`).
- **nginx.** Check `autoindex on`, sensitive locations without `deny`, missing upload
  limits, and `alias` path traversal caused by trailing slashes.
- **CI/CD.** Check plaintext secrets in workflows, misuse of `pull_request_target`, and
  third-party actions pinned only by tag.
- **Permissions.** Check whether `.git`, `.env`, backups (`.sql`, `.bak`, `.zip`) are
  deployed inside the web root.
- **CORS.** Check for `Access-Control-Allow-Origin: *` combined with
  `Allow-Credentials: true` (an invalid but common misconfiguration), or reflected
  `Origin` with credentials allowed.

## 8. Dependencies and components

- Check dependency manifests for high-risk old versions: `lodash < 4.17.21`,
  `log4j < 2.17`, old `fastjson`, `openssl` 1.x, `node < 18`.
- If network access is available, run `npm audit --omit=dev`, `pip-audit`,
  `go list -m -u all`, or equivalent tools.
- Identify unmaintained dependencies (no update for more than two years and known issues).
- Verify that lock files match manifests and are committed.
