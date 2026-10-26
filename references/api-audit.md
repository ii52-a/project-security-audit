# API Security Review Checklist

Enumerate every interface first, then review each one. For each interface, answer four
questions: **Who can call it? Is input validated? Is output redacted? Is it rate-limited?**

## 1. Interface inventory (do this first)

Extract the complete inventory and write it to **Appendix A** of the report (format in
`SKILL.md`):

- Route definitions (Express `app.get/post`, FastAPI `@router`, Spring
  `@RequestMapping`, Gin `r.GET`, and equivalents).
- RPC and GraphQL schemas, WebSocket event names, and message-queue consumers.
- Administrative endpoints, internal debug endpoints, scheduled jobs, and CLI entry
  points. These are interfaces too.

Inventory fields: method + path + handler location + authentication middleware
(present/absent) + whether the endpoint is publicly exposed.

## 2. Authentication

- Verify that every endpoint declares its authentication requirement. Look for endpoints
  that "fell through" because a new route was added without middleware.
- Determine where the token comes from (header, cookie, or URL parameter). **A token in a
  URL is P1** because it is written to logs and the `Referer` header.
- Check token expiration and refresh behavior, and whether long-lived API keys have a
  rotation mechanism.

## 3. Authorization and object-level access control

- **Horizontal privilege escalation (IDOR).** For every endpoint that fetches a resource
  by ID, verify that ownership is checked. Before `findById(id)`, look for a constraint
  such as `where userId = currentUser`.
- **Vertical privilege escalation.** Check whether a normal user can call administrative
  endpoints, and whether role checks are enforced centrally in middleware or scattered
  and incomplete.
- **Function-level authorization.** High-risk operations such as export, bulk delete, and
  payment-price changes SHOULD require a second check (idempotency token or signature).

## 4. Input handling

- Verify schema validation for all inputs (query, body, path, header, files) using zod,
  joi, pydantic, class-validator, or an equivalent. Check whether unvalidated fields are
  passed directly to the ORM or SQL (mass-assignment risk: `req.body` passed directly to
  `update`).
- Check numeric bounds: pagination size limits (for example `size=999999999`) and whether
  monetary amounts are computed server-side.
- Check type confusion: `Array.isArray` checks, and string-versus-object confusion
  (NoSQL injection such as `{"$gt": ""}`).
- Verify sanitization of rich-text and HTML input.

## 5. Output handling and information disclosure

- Check whether responses contain extra fields: password hashes, internal IDs, or other
  users' private fields. Review serialization configuration (`toJSON`, serializers, and
  `select *` followed by returning the entire row).
- Check whether error responses distinguish "user does not exist" from "wrong password"
  (account enumeration), and whether stack traces or SQL are returned to clients.
- Check whether pagination endpoints allow unlimited traversal and bulk extraction.

## 6. Rate limiting and abuse prevention

- Verify rate limits on login, registration, password reset, SMS/email sending, and
  payment endpoints. An unlimited SMS endpoint enables SMS bombing and is P1.
- Check for a global rate-limit middleware, whether it keys on both IP and account, and
  whether distributed deployments use Redis rather than in-process memory.
- Check where CAPTCHA is required and how long it remains valid.

## 7. CORS and cross-origin access

- Determine whether the configuration is a hard-coded allowlist or a wildcard/reflected
  `Origin`. When `credentials: true`, the origin MUST be allow-listed.
- Check whether `null` origin is allowed (exploitable in iframe-sandbox scenarios).

## 8. File upload and download endpoints

- Follow `server-vulns.md` Section 4. At the API layer, additionally check the domain of
  the URL returned after upload, and whether downloads verify a signature and expiration
  (to prevent enumeration of other users' files).

## 9. Third-party callbacks and webhooks

- Verify signature or certificate validation on payment callbacks, and confirm that the
  server does not trust a client-supplied amount or payment status.
- Verify idempotency: a repeated notification MUST NOT trigger duplicate shipment or
  duplicate credit.

## 10. API documentation and exposed surface

- Check whether Swagger/OpenAPI documentation, GraphQL playground, Druid, or Actuator is
  exposed in production.
- Check whether `OPTIONS`/`TRACE` and other unnecessary methods are disabled, and whether
  HTTP and HTTPS are both open while HTTP does not redirect.
