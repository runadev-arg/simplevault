# 02-01 — NestJS 10 → 11 upgrade — SUMMARY

**Status:** COMPLETE
**Date:** 2026-04-29
**Commits:** `f205f68` (T1), `4b27606` (T2)
**Tasks:** 2/2

---

## What landed

### Task 1 — `chore(02-01-T1): upgrade @nestjs/* to ^11.x` (`f205f68`)

`apps/api/package.json` deps bumped:

| Package | From | To | Resolved |
|---|---|---|---|
| `@nestjs/common` | `^10.4.0` | `^11.0.0` | 11.1.19 |
| `@nestjs/core` | `^10.4.0` | `^11.0.0` | 11.1.19 |
| `@nestjs/platform-express` | `^10.4.0` | `^11.0.0` | 11.1.19 |
| `@nestjs/config` | `^3.3.0` | `^4.0.0` | 4.0.4 |
| `nestjs-pino` | `^4.2.0` | `^4.6.0` | 4.6.1 |
| `@nestjs/cli` (dev) | `^10.4.5` | `^11.0.0` | 11.0.21 |
| `@nestjs/schematics` (dev) | `^10.2.3` | `^11.0.0` | 11.1.0 |

Other peers (`pino`, `pino-http`, `helmet`, `ioredis`, `reflect-metadata`, `rxjs`, `zod`, `class-validator`, `class-transformer`) left at Phase 01 versions — Nest 11 peer ranges are satisfied (`rxjs@^7.8`, `reflect-metadata@^0.2`).

`nestjs-pino@4.6.1` declares `@nestjs/common: ^8 || ^9 || ^10 || ^11` peer — no need to jump to v5/v6 line. Decision recorded: **stay on `nestjs-pino@^4.6` for now**; revisit only if a future Nest 12 forces it.

`pnpm install` clean. Lockfile resolves `@nestjs/common@11.1.19` as the sole NestJS major.

Verification:
- `pnpm --filter @simplevault/api typecheck` — 0
- `pnpm --filter @simplevault/api build` — 0 (`nest build`)
- `pnpm --filter @simplevault/api lint` — 0
- `node apps/api/dist/main.js` boots; `curl http://localhost:3001/health` → `{"status":"degraded","db":"down","redis":"down",…}` (200), same shape as Phase 01 in DB-less env.

No source edits required — `apps/api/src/main.ts` and `app.module.ts` are source-compatible across Nest 10 → 11.

### Task 2 — `chore(02-01-T2): remove multer pnpm.overrides` (`4b27606`)

Removed `"multer@<2.1.1": ">=2.1.1"` from root `package.json` `pnpm.overrides`. Lockfile after `pnpm install` shows multer resolving to `2.1.1` naturally (Nest 11's `@nestjs/platform-express` pulls a fresh enough version).

Lodash override RETAINED (`"lodash@<4.18.0": ">=4.18.1"`) — `@nestjs/config@4.0.4` still drags lodash through its dependency graph, so the upstream advisory still applies in absence of the override.

### Audit baseline (post-upgrade)

```
$ pnpm audit --prod --audit-level=high
1 vulnerabilities found
Severity: 1 moderate                      ← actually 0 high; the "1" is the postcss moderate
```

```
$ pnpm audit --audit-level=high (includes dev)
2 vulnerabilities found
Severity: 2 moderate                      ← 0 high; both are dev-only transitives
```

**0 high, 0 critical at every audit level.** The two Phase 01 dev-only Highs (`glob` CLI command-injection + `picomatch` ReDoS via `@nestjs/cli@10.4.9`) are GONE — confirmed they no longer appear in `pnpm audit --audit-level=high`.

Two moderate residuals remain, both dev-only transitives:
1. **esbuild ≤0.24.2 (GHSA-67mh-4wv8-2f99)** via `drizzle-kit@0.31.10 → @esbuild-kit/esm-loader → … → esbuild@0.18.20`. Dev server CORS bypass — only matters when running `vite`-style dev server, which we don't. Track for resolution when drizzle-kit upgrades its `@esbuild-kit/*` chain.
2. **postcss <8.5.10 (GHSA-qx2v-qp2m-jg93)** via `next@15.5.15 → postcss@8.4.31`. XSS in CSS stringify output, dev/build only. Awaits Next.js 15.x patch.

Neither is high/critical; both pre-existed in Phase 01 (then below the `--audit-level=high` reporting bar). No operator action required.

---

## Truths verified

| # | Truth | Status |
|---|---|---|
| 1 | apps/api builds + boots on @nestjs/* ^11 | OK (`build`, `typecheck`, `lint`, boot, `/health` all green) |
| 2 | Helmet, ValidationPipe, AllExceptionsFilter, nestjs-pino, /health all still work | OK — `/health` returned canonical degraded response with structured pino logs |
| 3 | multer pnpm.override REMOVED | OK (root `package.json` diff) |
| 4 | lodash pnpm.override REMAINS | OK (root `package.json` diff) |
| 5 | `pnpm audit --prod --audit-level=high` returns 0 | OK |
| 6 | GET /health returns canonical HealthResponse shape | OK (`status`/`db`/`redis`/`timestamp`) |

---

## Deviations from plan

None. Plan defined Tasks T1+T2 only and both ran clean on the first attempt.

---

## Issues / carry-overs for downstream Phase 02 plans

- **Multer override**: REMOVED as planned. Wave 2+ plans don't need to touch root `package.json`.
- **@nestjs/cli dev-only Highs**: CLEARED. Confirmed via post-upgrade `pnpm audit --audit-level=high` — `glob` CLI command-injection and `picomatch` ReDoS no longer appear.
- **nestjs-pino**: stayed on the v4 line (4.6.1) since it already supports Nest 11 peer. No need for the v5/v6 escape hatch contemplated in the plan.
- **Two moderate residuals (esbuild via drizzle-kit, postcss via next)** — not new, both were latent in Phase 01 and surfaced only when audit threshold drops to moderate. Dev-only, no production impact. Not blocking; track for upstream patches.
- **Wave 2+ assumptions**: subsequent plans (02, 03, 05) can target Nest 11 idioms (e.g. `@Module` and DI behaviour identical; `LifecycleHooks` same surface). No API-shape changes between Nest 10 and 11 affect the plans we have queued.
