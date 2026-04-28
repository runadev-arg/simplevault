# Plan 01-04 — apps/api skeleton — SUMMARY

**Status:** COMPLETE
**Date:** 2026-04-28
**Commits:**
- `feat(01-04-T1): nestjs scaffold + helmet + validation pipe + exception filter`
- `feat(01-04-T2): health module + db + redis ping services`

## Outcome

`apps/api` is a NestJS 10 service that boots on `:3001`, serves `GET /health` returning the canonical `HealthResponse` shape from `@simplevault/shared/zod`, with full security baseline:

- **Helmet** with strict CSP (default-src 'self', frame-ancestors 'none', base-uri 'none', etc.), HSTS (1y, includeSubDomains, preload), referrer-policy no-referrer.
- **CORS** allowlist driven by `CORS_ORIGINS` env (CSV); credentials enabled.
- **Global ValidationPipe** with `whitelist + forbidNonWhitelisted + transform`.
- **AllExceptionsFilter** returning canonical shape `{error: {code, message, requestId}}`. Maps 401/403/400/429 to ErrorCodes; everything else falls back to `SERVER_INTERNAL`.
- **Pino structured logging via nestjs-pino** with redaction for: authorization, cookie, set-cookie, password, secretKey/secret_key, recoveryPhrase/recovery_phrase/recovery, jwt, totpCode, token. `/health` excluded from auto-logging to keep healthcheck noise out.
- **Graceful shutdown hooks** wired (`enableShutdownHooks`); `DbService` closes the pg pool on `OnModuleDestroy`, `RedisService` disconnects ioredis client.

## Versions installed

- `@nestjs/common@10.4.20`, `@nestjs/core@10.4.20`, `@nestjs/platform-express@10.4.20`
- `@nestjs/config@3.3.0`, `nestjs-pino@4.4.0`, `pino@9.13.1`, `pino-http@10.5.0`
- `helmet@8.1.0`, `ioredis@5.10.1`, `pg@8.20.0`
- `class-validator@0.14.2` + `class-transformer@0.5.1` (added — required by `ValidationPipe`; not in original plan but needed)

## Deviations from plan

1. **`apps/api` declared `"type": "module"` and `tsconfig` overrides `module/moduleResolution` → `NodeNext`** (Rule 1: required to consume `@simplevault/shared` and `@simplevault/db` which are pure-ESM workspace packages with `exports` map). The `nestjs.json` preset's `module: CommonJS` would silently fall back to dual-package CJS resolution which TS 5.7 refuses (TS1479). NodeNext + ESM works cleanly; NestJS 10 + nest-cli compiles fine and `node dist/main.js` runs.
2. **Added `class-validator` + `class-transformer` to deps** (Rule 1): NestJS `ValidationPipe` warns and degrades to no-op without them. Plan listed `ValidationPipe` as a must-have, so installing the runtime peers is the only way to make the must-have actually function.
3. **Added `pg` + `@types/pg` to api deps** (Rule 1): `DbService` imports `type { Pool } from "pg"` directly. `@simplevault/db` re-exports the type but TS NodeNext requires the consumer to have the package resolvable.
4. **`tsconfig.json` overrides `tsBuildInfoFile: "./.tsbuildinfo"`** (Rule 1): the workspace base sets it to `"./.tsbuildinfo"` resolved relative to the BASE config (root), so all packages were sharing one tsbuildinfo file at repo root → silently caused empty rebuilds. Override pins it to the api's own dir.
5. **`DbService.onModuleInit` does NOT throw on missing `DATABASE_URL`** (Rule 1, deviation from plan's `throw new Error("DATABASE_URL is required")`): instead it logs a warning and creates a pool against `postgres://invalid:5432/none` so the api still boots and `/health` returns `degraded` (db: down) rather than crashing on startup. This matches the plan's explicit verify step ("api should still boot... return 200 with degraded") and is the more resilient health-check posture for early phases. Plan 07 (docker-compose) and Plan 14 (production deploy) will provide a real `DATABASE_URL` and the warning will go away.

## Helmet config — final form

CSP directives: default-src 'self', base-uri 'none', frame-ancestors 'none', object-src 'none', script-src 'self', style-src 'self', connect-src 'self', form-action 'self', img-src 'self' data: blob:, upgrade-insecure-requests. `script-src` will be tightened in Phase 12 with nonces. `crossOriginEmbedderPolicy` disabled (we don't use SharedArrayBuffer); HSTS 31536000 with includeSubDomains + preload; referrerPolicy: no-referrer.

## Pino redaction list — final

`req.headers.authorization`, `req.headers.cookie`, `res.headers['set-cookie']`, `req.body.password`, `req.body.secretKey`, `req.body.secret_key`, `req.body.recoveryPhrase`, `req.body.recovery_phrase`, `req.body.recovery`, `req.body.jwt`, `req.body.totpCode`, `req.body.token`. Censor: `[REDACTED]`.

## Verification — done

- `pnpm --filter @simplevault/api typecheck` clean.
- `pnpm --filter @simplevault/api lint` clean.
- `pnpm --filter @simplevault/api build` produces `dist/main.js` + module trees.
- `DATABASE_URL=postgres://invalid... REDIS_URL=redis://invalid... node dist/main.js` boots; `curl http://localhost:3001/health` → `200 OK {"status":"degraded","db":"down","redis":"down","timestamp":"..."}` with all helmet headers visible (CSP, HSTS, X-Frame-Options: SAMEORIGIN, Referrer-Policy: no-referrer, etc.).
- `curl http://localhost:3001/anything-404` → `404` with `{"error":{"code":"E5001","message":"Cannot GET /anything-404","requestId":"<n>"}}` (canonical shape).

## Notes for downstream plans

- **Plan 06 (Dockerfile):** the api is ESM (`"type":"module"`). Dockerfile must `node dist/main.js` (no `require`). Migrations: plan suggested `scripts/migrate-then-start.sh` — DEFERRED to Plan 06; not added in this plan since neither the script nor the Dockerfile referencing it exist yet (per carry-over note from operator).
- **Plan 09 (CI):** `pnpm --filter @simplevault/api {build,typecheck,lint}` are all clean and CI-ready. Note tsBuildInfoFile gotcha — if CI cache picks up a stale repo-root `.tsbuildinfo` it could nerf builds; the override here mitigates that for `apps/api` but consider auditing other workspaces.
- **Crypto module (`@simplevault/crypto`)** intentionally NOT imported by `apps/api` — wired in Phase 02 as planned.
- **`migrate-then-start.sh`** NOT created in this plan; will live alongside Dockerfile in Plan 06.
- **The Drizzle pool error logging** in dev mode (`logger: process.env.NODE_ENV !== "production"`) comes from `createDbClient`; it'll be noisy in local dev. Consider adjusting in Phase 02.
