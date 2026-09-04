# Deferred Items — Phase 04 (Frontend Split)

Items discovered during execution that are out of scope for the current plan/task and were not fixed. Logged per executor scope-boundary rules.

## From 04-01 (Task 2: npm install)

- **`npm audit` reports 8 transitive dev-dependency vulnerabilities** (2 low, 1 moderate, 5 high) after regenerating `package-lock.json` against the pinned toolchain versions specified in `04-PATTERNS.md`/`04-RESEARCH.md`: `@babel/core`, `browserslist`, `esbuild` (dev-server-only request/response issue), `nanoid`, `postcss`, `postcss-selector-parser`, `undici`, `vite` (dev-server path traversal / `server.fs.deny` bypass, transitively via `vite@^5.4.10`).
  - All are transitive deps of the pinned `vite ^5.4.10` / `postcss ^8.4.47` / `tailwindcss ^3.4.14` toolchain, not direct runtime dependencies of the shipped app.
  - RESEARCH.md explicitly verified these pinned major versions are mutually compatible (vitest 5 / vite 8 produce a real ERESOLVE peer conflict in this sandbox) and instructed the executor not to bump any version to a newer major.
  - Fixing these would require `npm audit fix --force`, which bumps majors and directly contradicts the plan's pinned-version instruction — out of scope for 04-01.
  - Most flagged issues are dev-server-only (local `vite dev` request handling, source-map path traversal during local development) and do not affect the built/served production bundle.
  - Deferred to a future phase/plan that explicitly revisits the toolchain version pins (or is scoped to run `npm audit fix` and re-verify against RESEARCH.md's ERESOLVE finding).
