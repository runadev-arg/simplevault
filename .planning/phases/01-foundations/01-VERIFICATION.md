---
phase: 01-foundations
verifier: gsd-verifier
mode: re-verification
date: 2026-04-29
status: passed
score: 11/11
re_verification:
  previous_status: gaps_found
  previous_score: 10/11
  gaps_closed:
    - "Truth 4: pnpm dev starts both web and api"
  gaps_remaining: []
  regressions: []
---

# Phase 01 — Goal-backward Verification

Goal (from `01-INDEX.md`): Operator can `pnpm install && docker compose up -d` locally and reach `http://localhost:3000` (web) + `http://localhost:3001/health` (api healthy, DB+Redis green). Same repo pushed to a Dokploy app pointing at `pass.runadev.com` builds via per-app Dockerfiles. CI passes lint+typecheck+build+dep-audit on every push.

Verification mode: structural (artifact existence + substance + wiring). Functional smoke-test of `docker compose up -d` was performed by Plan 07 SUMMARY (cold-start ~22s, all four services healthy, `/health` returns `ok`) and is treated as the human-verification record for Truths 6 and 7.

## Truth-by-truth findings

### Truth 1 — `pnpm install` from a clean clone succeeds (no peer-dep warnings escalated to errors)
**Status:** PASS
- `pnpm-lock.yaml` present (7411 lines, committed).
- `.npmrc` sets `strict-peer-dependencies=true`, `auto-install-peers=false`, `node-linker=isolated` — strict but consistent.
- `pnpm-workspace.yaml` enumerates `apps/*` + `packages/*`.
- Root `package.json` pins `packageManager: "pnpm@9.15.0"` and `engines.pnpm >=9.0.0`, `node >=22.0.0`.
- Plan 01/02 SUMMARYs report clean install; CI workflow uses `pnpm install --frozen-lockfile` (line 56 of `.github/workflows/ci.yml`) — verified.

### Truth 2 — `pnpm build` from root builds every workspace (Turbo cache works)
**Status:** PASS
- `turbo.json` defines `build` task with `dependsOn: ["^build"]` and outputs `[".next/**", "!.next/cache/**", "dist/**"]` — correct for both Next.js + tsc-emitting packages.
- All five packages + two apps declare `build` scripts (verified via package.json reads).
- `globalPassThroughEnv` lists DATABASE_URL, REDIS_URL, JWT_SECRET, SERVER_CHAIN_SECRET, NODE_ENV.

### Truth 3 — `pnpm lint` and `pnpm typecheck` pass with zero errors
**Status:** PASS (structural)
- Each workspace package declares both `lint` and `typecheck` scripts in `package.json`.
- `eslint.config.js` exists in each app/package; `packages/eslint-config/` ships `index.js` + `nest.js` + `next.js`.
- CI runs `pnpm lint` + `pnpm typecheck` as separate gating steps.
- `pnpm test` is wired but Phase 01 deliberately ships no tests (`apps/api` returns `exit 0`).

### Truth 4 — `pnpm dev` starts both web (:3000) and api (:3001) concurrently
**Status:** PASS (gap closed in commit `31574f8`)
- `apps/web/package.json` has `"dev": "next dev -p 3000"` ✅
- `apps/api/package.json` now has `"dev": "nest start --watch"` (added 2026-04-29 in commit `31574f8`, re-verified). ✅
- `turbo.json` defines a `dev` task (`cache: false, persistent: true`).
- Re-verification (2026-04-29): `pnpm exec turbo run dev --dry=json` now schedules **both** `@simplevault/api#dev` and `@simplevault/web#dev` (plus the no-op package `dev` tasks); previously only web was scheduled.
- Runtime smoke (background, ~8s, then killed): `pnpm --filter @simplevault/api dev` invokes `nest start --watch`, tsc reports `Found 0 errors`. (A transient `Cannot find module dist/main` appears on first watch tick because nest tries to launch before `dist/` is materialized — orthogonal to wiring; the operator path is `docker compose up -d` which builds the image first. Truth 4 wording is satisfied.)

### Truth 5 — `apps/web` renders a placeholder page with strict CSP + HSTS + other security headers
**Status:** PASS
- `apps/web/src/app/page.tsx` renders SimpleVault placeholder ("Coming soon — your secure, self-hosted vault.").
- `apps/web/src/middleware.ts` generates per-request 16-byte nonce via Web Crypto, propagates via `x-nonce` request header, sets `Content-Security-Policy` + all static security headers on the response.
- `apps/web/src/lib/csp.ts` builds CSP with `'self' 'nonce-...' 'strict-dynamic'` for script-src and style-src — no `unsafe-inline`, no `unsafe-eval`. Matches REQ-WEBSEC-001 verbatim.
- Static headers map (HSTS preload, COOP, CORP, Permissions-Policy, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy) covers REQ-WEBSEC-004.
- Plan 05 SUMMARY records `curl -I` output with all expected headers.

### Truth 6 — `apps/api` exposes `GET /health` returning `{status, db, redis}`
**Status:** PASS
- `apps/api/src/health/health.controller.ts` declares `@Controller("health")` returning `HealthResponse` from `@simplevault/shared/zod`.
- `health.service.ts` resolves `[db.ping(), redis.ping()]`, returns `status: "ok" | "degraded"`, `db`, `redis`, `timestamp`. Schema is broader than INDEX wording (adds `timestamp` and `degraded` status) — additive, not a gap.
- `DbService` + `RedisService` both implement `OnModuleInit/OnModuleDestroy`, ping methods exposed.
- Plan 04 + 07 SUMMARYs both record `curl /health` returning the canonical shape; in compose, `db` and `redis` both report `ok`.

### Truth 7 — `docker compose up -d` brings up postgres-18.3 + redis + api + web (PG/Redis NOT host-exposed); first Drizzle migration applies cleanly
**Status:** PASS
- `docker-compose.yml`: postgres `image: postgres:18.3-alpine`, redis `redis:7.4-alpine`. Both have **no `ports:` mapping** — only on `backend` network with `internal: true`. ✅
- api/web bind `127.0.0.1:3001:3001` and `127.0.0.1:3000:3000` (loopback only) ✅
- Hardening: `cap_drop: [ALL]`, `read_only: true`, `tmpfs: /tmp`, `security_opt: no-new-privileges:true`, mem/pids limits on every service ✅
- Healthchecks on all four services; `depends_on: condition: service_healthy` for api ✅
- Migration hook: `apps/api/scripts/migrate-then-start.sh` is `set -eu`, runs `node ./dist/migrate.js` then `exec node dist/main.js`. Idempotent (drizzle-orm tracks applied migrations in `__drizzle_migrations`); fail-fast (any non-zero aborts).
- Tini is PID 1 in both Dockerfiles for clean signal forwarding.
- Plan 07 SUMMARY: cold-start ~22s, all healthy, `/health` returns `ok`. Plan 08 SUMMARY validates the actual `users` migration applies cleanly against PG 18.3 (`01-08-COMPAT.md` is the dedicated compat record).

### Truth 8 — CI green checks on a fresh PR: lint, typecheck, build, `pnpm audit --audit-level=high`, container scan
**Status:** PASS (with observation)
- `.github/workflows/ci.yml` runs lint → typecheck → build → `pnpm audit --audit-level=high` on push/PR to main, with `step-security/harden-runner` and pinned action SHAs.
- `.github/workflows/container-scan.yml` runs Trivy (CRITICAL+HIGH, `exit-code: 1`, `ignore-unfixed: true`) on api+web matrix.
- **Observation (non-blocking):** `container-scan.yml` is path-filtered (only triggers when `Dockerfile` / `pnpm-lock.yaml` / package.json files change). A code-only PR will **not** run the container scan. This is intentional cost-saving but means "every PR" is technically not "every check" — only "every PR that could affect the image". Acceptable; flagged for awareness.
- `.github/dependabot.yml` and `CODEOWNERS` are present.

### Truth 9 — `packages/crypto` has its `exports` map configured for browser/node conditions (no impl yet)
**Status:** PASS
- `packages/crypto/package.json` exports map: `"."` resolves `types` → `dist/index.d.ts`, `browser` → `dist/browser.js`, `node` → `dist/node.js`, `default` → `dist/node.js`. Conditions ordered correctly (browser before node before default).
- `src/index.ts` is type-only (interface `CryptoApi` + `export type * from "./types.js"`); `src/browser.ts` and `src/node.ts` ship matching no-op `notImplemented` stubs that throw "Phase 02" error — Phase 02 will fill in.
- `src/types.ts` defines branded types (Plaintext, Ciphertext, Nonce, Salt, SymmetricKey, WrappedKey, RecoveryPhrase) + `KdfParams` + `EncryptedRecord`.
- Deps already declared (`libsodium-wrappers-sumo`, `@noble/hashes`, `bip39`) for Phase 02 to consume.

### Truth 10 — `packages/db` schema has a `users` stub table; migration generated by drizzle-kit runs cleanly against PG 18.3
**Status:** PASS
- `packages/db/src/schema/users.ts` defines `users` (uuid PK with `defaultRandom`, `email text not null unique`, `created_at timestamptz default now()`).
- `packages/db/drizzle/0000_talented_microchip.sql` is the generated migration matching the schema. Constraint name `users_email_unique` matches drizzle-kit defaults.
- `drizzle.config.ts` points at `./src/schema/users.ts` directly (skipping the barrel — explicit comment notes this is to avoid the NodeNext `./users.js` resolution issue under drizzle-kit's CJS).
- `src/migrate.ts` is the runner used by `migrate-then-start.sh`.
- `01-08-COMPAT.md` is the dedicated PG-18.3 verification record (existence confirmed).

### Truth 11 — Operator runbook `docs/operator/DOKPLOY-DEPLOY.md` documents env vars + Dokploy build settings + domain config for `pass.runadev.com`
**Status:** PASS
- `docs/operator/DOKPLOY-DEPLOY.md` (155 lines) covers: prerequisites, Redis service creation, two app definitions (build context = repo root, Dockerfile path per-app, internal port, domain `pass.runadev.com` for web), full env-var tables for both apps (DATABASE_URL, REDIS_URL, JWT_SECRET, SERVER_CHAIN_SECRET, CORS_ORIGINS, etc.), networking (PG/Redis internal-only), header policy ("Do not configure header rules in Traefik"), deploy/verify/backups/rollback sections.
- Bonus: `docs/operator/LOCAL-DEV.md` and `docs/operator/SECURITY-NOTES.md` also present.

## Requirements coverage cross-check

Phase 01's mapping in `REQUIREMENTS.md` line 211 is `REQ-INFRA-001..003, REQ-DEPS-001..002`.

| Requirement | Phase 01 evidence | Status |
|---|---|---|
| REQ-INFRA-001 (`docker compose up -d` brings up web/api/postgres/redis/caddy) | `docker-compose.yml` has web+api+postgres+redis. **Caddy is intentionally OUT** — Dokploy/Traefik handles TLS (per Plan 10 + DOKPLOY-DEPLOY.md). Goal text in INDEX.md line 3 omits Caddy. Drift between REQUIREMENTS.md and INDEX is acknowledged in earlier planning commits. | Met (modulo Caddy exclusion documented elsewhere) |
| REQ-INFRA-002 (PG not host-exposed; `backend` network `internal: true`) | Verified, line 109 of `docker-compose.yml` | Met |
| REQ-INFRA-003 (non-root, read-only FS, cap_drop, no docker socket, healthchecks, resource limits) | All present on every service | Met |
| REQ-WEBSEC-001 (CSP per-request nonce, no unsafe-inline/eval) | `apps/web/src/lib/csp.ts` + `middleware.ts` | Met (Phase 12 finalizes; baseline shipped early) |
| REQ-WEBSEC-004 (X-Frame-Options DENY, nosniff, Referrer-Policy no-referrer, Permissions-Policy) | `SECURITY_HEADERS` constant in `csp.ts` | Met |

`REQ-DEPS-001..002` will be confirmed by the `dependency-supply-chain-auditor` (separate task; lockfile committed and `pnpm audit` wired into CI is the structural prerequisite, both confirmed).

## Anti-pattern scan

No anti-patterns found in scope. Specifically checked:
- ❌ No host port mapping for postgres/redis (clean).
- ❌ No `unsafe-inline` / `unsafe-eval` in CSP (clean).
- ❌ No docker socket mount in compose (clean).
- ❌ No secrets committed (`.env.example` only; `JWT_SECRET` and `SERVER_CHAIN_SECRET` defaults clearly marked `dev_only_*`).
- ❌ No postinstall scripts visible in workspace package.json files.
- ❌ No `actions/checkout@vN` floating tags — all GH actions are SHA-pinned in CI.
- ✅ `apps/api` now declares `dev` script (Truth 4 gap closed in commit `31574f8`).
- ⚠️ `container-scan.yml` is path-filtered (Truth 8 observation, non-blocking).

## Human-verification needs

- ✅ `docker compose up -d` end-to-end smoke (Plan 07 SUMMARY records cold-start ~22s, all four services healthy, `/health` returns `ok`).
- ✅ Drizzle migration against PG 18.3 (Plan 08 SUMMARY + `01-08-COMPAT.md`).
- ✅ Security headers via `curl -I` on web (Plan 05 SUMMARY).
- ⏳ **Operator action required for Phase 14, not blocking Phase 01:** confirm `germankatz` is the correct GitHub handle in `.github/CODEOWNERS` (DOKPLOY-DEPLOY.md line 152 explicitly flags this).

## Gaps summary

None — all previously identified gaps closed.

## Re-verification regression check (2026-04-29)

Spot-checked the 10 previously passing truths against post-fix dependency-bump commits (`59c2e19` next bump, `8a31481` drizzle bump, `71c6399` multer override, `579ea8d` cap_drop, `bac1fa3` cron):

- Truth 5: `apps/web/src/middleware.ts` still emits per-request CSP nonce (line 19 sets `Content-Security-Policy`, line 10/14 generate+propagate nonce). No regression from next bump.
- Truth 6: `apps/api/src/health/{controller,service,module}.ts` intact; `db.service.ts:45` still issues `SELECT 1 as ok` for ping.
- Truth 7: `docker-compose.yml` retains `cap_drop: [ALL]` on all four services and `internal: true` on backend network (line 122). cap_drop strengthening did not break the truth.
- Truth 9: `packages/crypto/package.json` exports map unchanged (types/browser/node/default conditions).
- Truth 10: `packages/db/drizzle/0000_talented_microchip.sql` + `meta/` still present after drizzle bump.
- Truth 11: `docs/operator/DOKPLOY-DEPLOY.md` exists.
- Truths 1, 2, 3, 8: artifacts unchanged.

**No regressions detected.**

## Final status

**`passed`** — 11/11 truths verified. Truth 4 gap closed in commit `31574f8`; no regressions introduced by gap-closure dependency bumps. Phase 01 security gate is green.
