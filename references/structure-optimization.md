# Project Structure Assessment and Optimization Standard

## 1. Structure assessment (grade each item: Meets / Partially meets / Does not meet)

### 1.1 Directory organization

- Clear layering: entry points, routes/controllers, business logic, data access, and shared
  utilities have identifiable boundaries. Business logic MUST NOT leak into route handlers
  (a thousand-line controller is a counterexample).
- Organizing by feature or by type is acceptable, but the choice MUST be **consistent**.
  Mixing both without explanation does not meet the standard.
- Shared code is reasonably extracted. Large copy-paste duplication (a repeated block over
  50 lines) does not meet the standard.
- Dead code: unreferenced modules, commented-out logic, and multiple historical
  implementations (`utils_v2`, `old_` directories).

### 1.2 Configuration and environment

- Configuration is separated from code: no environment-specific values hard-coded
  (database addresses or switches embedded in code).
- Environment isolation: dev/test/prod configuration sources are explicit; `.env.example`
  exists; configuration loading is typed and validated (schema validation with fail-fast at
  startup).
- Sensitive configuration is not committed. Cross-reference the Stage 2 security findings.

### 1.3 Engineering practice

- A README exists and covers startup, environment requirements, and directory layout.
- The dependency manifest is complete (a package imported but not declared does not meet
  the standard), and a lock file exists and is committed.
- Basic quality infrastructure exists: lint configuration, formatting configuration, and at
  least smoke tests. Tests SHOULD cover core paths.
- Build and startup are one-command operations (script, Makefile, or npm scripts) with no
  undocumented tribal steps.
- Version control: commit history is readable (not mandatory); binary and large files
  SHOULD use LFS or an artifact repository rather than the repository itself.

## 2. Optimization items (output in priority order; each item = current problem + concrete change)

### 2.1 Code-quality items

1. List files over 500 lines and functions over 80 lines, and recommend a decomposition by
   responsibility, not by line count alone.
2. Oversized dependencies: remove a large dependency introduced for a small function (for
   example, pulling in lodash for a UUID).
3. Standardize error handling. When throw, return codes, and swallowed exceptions (empty
   `catch`) are mixed, define one error model and list every empty `catch`.
4. Standardize logging: one logging library and level scheme; no `console.log` on
   production paths.

### 2.2 Maintainability items

5. Decouple the API layer from the data layer. When SQL/ORM calls are scattered through
   routes, extract a data-access layer; this also provides one place for injection
   defenses.
6. Type safety: in TypeScript projects, reduce `any` proliferation (count `: any`). In
   untyped JavaScript projects, add JSDoc to public interfaces or migrate incrementally.
7. Consolidate magic values: repeated URLs, timeouts, and thresholds become constants or
   configuration.

### 2.3 Engineering items

8. Add CI with at least lint, test, and build stages. For a project without CI, this is the
   first recommendation.
9. Add `.editorconfig`, lint, and formatting to eliminate style noise.
10. Complete documentation: API documentation (OpenAPI annotations or export), deployment
    documentation, and environment-variable reference.

## 3. Output requirements

- Summarize the assessment in one table with the grade for each standard, then expand only
  on "Partially meets" and "Does not meet" items.
- Order optimization items by "high benefit, low effort → high benefit, high effort →
  nice-to-have". Estimate effort for each (hours / days / weeks).
- Keep this section separate from performance analysis (`performance.md`); do not mix them.
