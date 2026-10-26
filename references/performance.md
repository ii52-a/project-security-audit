# Performance Optimization Analysis Checklist

This section is advisory analysis, not vulnerabilities. Do not mix these items into the
P0–P3 finding table. Group output as **database → application → front end/network →
infrastructure**, and include the evidence location, estimated impact (high/medium/low),
recommendation, and effort for each item.

## 1. Database layer (usually the largest gain; check first)

- **N+1 queries.** A query inside a loop (`for ... await db.query`), or ORM relations
  lazily loaded inside a loop. Fix with a batched `IN` query or eager loading.
- **Missing-index signals.** Compare `WHERE`/`ORDER BY` columns with index definitions. If
  you cannot confirm, mark `DBA review with EXPLAIN required`.
- **`SELECT *`.** A wide table (TEXT/BLOB columns) is fetched row by row in full.
- **Unbounded large queries.** Fetching an entire table and filtering or aggregating in
  memory.
- **Connection pooling.** A new connection per request, or a pool hard-coded to size 1.
  Check whether connections are reused (singleton client versus per-function creation).
- **Oversized transactions.** HTTP calls or heavy computation inside a transaction, holding
  locks for a long time.
- **Synchronous blocking work.** Large files or images stored in the database instead of
  object storage.

## 2. Application layer

- **Serial work that could be parallel.** Independent I/O operations executed serially
  instead of with `Promise.all` or `asyncio.gather`.
- **Repeated computation.** The same data queried multiple times within one request, with
  no request-level cache or memoization.
- **Synchronous CPU-bound work.** Encryption, compression, or image processing on Node's
  single thread blocking the event loop (move to a worker or queue); pure-CPU Python loops.
- **Missing cache.** Hot data (configuration, home page, leaderboard) with no cache layer,
  or a cache without TTL or invalidation policy.
- **Startup performance.** Synchronously requiring every module at entry, or warming
  everything at startup.
- **Memory risk.** Unbounded global maps or arrays (a cache without eviction is a slow
  leak).

## 3. Front end and network

- **Bundle size.** No code splitting (one bundle contains every route); whole-package
  imports (`import * as _ from 'lodash'`); full imports of large dependencies such as
  moment or antd.
- **Static assets.** Uncompressed images or legacy formats, no CDN, no gzip/brotli, no
  long-lived fingerprinted caching.
- **Critical path.** Render-blocking CSS/JS, serial first-screen request waterfalls,
  fonts without `font-display: swap`.
- **API design.** List pages fetch every field, no field selection, and no batch endpoint,
  causing multiple round trips.

## 4. Infrastructure and deployment

- No process supervision or graceful restart; a single instance with no horizontal-scaling
  design (in-memory sessions are an immediate scaling blocker).
- Synchronous log writes without rotation; no metrics or monitoring (inability to locate
  latency is itself a problem; rate it low-to-medium but report it).
- Build artifacts not minified or tree-shaken; Docker images include devDependencies and
  build caches (slow pulls).

## 5. Output format

```text
| ID | Category | Issue | Evidence | Impact | Recommendation | Effort |
|---|---|---|---|---|---|---|
| PERF-01 | Database | Per-row query inside a loop | src/dao/user.ts:57 | High | Use a batched IN query | Small |
```

End with a 3–5 sentence summary identifying the two or three changes with the largest
overall benefit: the "performance quick wins" list.
