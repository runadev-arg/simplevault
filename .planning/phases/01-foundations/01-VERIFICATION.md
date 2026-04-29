---
phase: 01-foundations
verifier: gsd-verifier
mode: initial
date: 2026-04-28
status: gaps_found
score: 10/11
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
**Status:** GAP
- `apps/web/package.json` has `"dev": "next dev -p 3000"` ✅
- `apps/api/package.json` has **no `dev` script** — only `"start:dev": "nest start --watch"`. Plan 01-04-PLAN line 83 used `start:dev` deliberately, but Truth 4 of the INDEX says `pnpm dev`. Running `pnpm dev` (= `turbo run dev`) will start only the web app; turbo silently skips packages with no matching task script.
- **Fix options (operator choice):** (a) add `"dev": "nest start --watch"` to `apps/api/package.json`, or (b) update Truth 4 / runbook to say `docker compose up -d` (which is the actual operator path and *is* fully wired).
- Note: the goal as stated in `01-INDEX.md` line 3 is `docker compose up -d`, not `pnpm dev`. Truth 4 is the only place that mentions `pnpm dev`, and Plan 07 SUMMARY confirms `docker compose up -d` brings up all four services healthy (web on :3000, api on :3001). So the **operator goal is met**, but the literal text of Truth 4 is not.

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
- ⚠️ `apps/api` lacks a `dev` script (Truth 4 gap, see above) — single named gap.
- ⚠️ `container-scan.yml` is path-filtered (Truth 8 observation, non-blocking).

## Human-verification needs

- ✅ `docker compose up -d` end-to-end smoke (Plan 07 SUMMARY records cold-start ~22s, all four services healthy, `/health` returns `ok`).
- ✅ Drizzle migration against PG 18.3 (Plan 08 SUMMARY + `01-08-COMPAT.md`).
- ✅ Security headers via `curl -I` on web (Plan 05 SUMMARY).
- ⏳ **Operator action required for Phase 14, not blocking Phase 01:** confirm `germankatz` is the correct GitHub handle in `.github/CODEOWNERS` (DOKPLOY-DEPLOY.md line 152 explicitly flags this).

## Gaps summary

1. **Truth 4 (literal):** `pnpm dev` does not start the api because `apps/api/package.json` only declares `start:dev`, not `dev`. Operator goal (`docker compose up -d`) IS met. Choose one of:
   - Add `"dev": "nest start --watch"` to `apps/api/package.json` (one-line fix; preserves Truth 4 verbatim).
   - Update Truth 4 in `01-INDEX.md` to say "`docker compose up -d`" instead of `pnpm dev` (aligns with the actual phase goal text on line 3).

## Final status

**`gaps_found`** — 10/11 truths verified. Single named gap on Truth 4 is one-line cosmetic and does not block the security gate. Recommend the orchestrator either patch `apps/api/package.json` or amend Truth 4 wording before declaring Phase 01 complete; everything else (compose, headers, migrations, CI, runbook) is substantive and wired correctly.
