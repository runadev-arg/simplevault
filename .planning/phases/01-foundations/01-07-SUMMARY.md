# Plan 01-07 — Local docker-compose + `.env.example` — SUMMARY

**Status:** ✅ Complete
**Date:** 2026-04-28
**Wave:** 6 (sequential after Wave 5)

## What shipped

- `docker-compose.yml` — local-dev stack: postgres-18.3-alpine, redis-7.4-alpine, api (built from `apps/api/Dockerfile`), web (built from `apps/web/Dockerfile`).
- `.env.example` — every env var consumed by compose + Dockerfiles documented with safe dev-only placeholders.

## Security baseline (verified)

| Check | Result |
|---|---|
| Postgres host port mapping | NONE (`docker compose port postgres 5432` → `:0`) |
| Redis host port mapping | NONE (`docker compose port redis 6379` → `:0`) |
| `backend` network `internal: true` | ✅ (`docker network inspect simplevault_backend --format '{{.Internal}}'` → `true`) |
| Healthchecks on every service | ✅ (postgres `pg_isready`, redis `redis-cli ping`, api/web Dockerfile HEALTHCHECK) |
| `depends_on: condition: service_healthy` | ✅ api waits for postgres + redis healthy |
| `cap_drop: [ALL]` on api+web | ✅ |
| `security_opt: [no-new-privileges:true]` on all 4 | ✅ |
| `read_only: true` rootfs on api+web | ✅ with `tmpfs: /tmp` (size 64m) for pino |
| Non-root user | ✅ (uid 100 `app` from Dockerfile) |
| Resource limits | ✅ `mem_limit` (256–512m) + `pids_limit` (100–200) per service |
| API port bound to 127.0.0.1 only | ✅ `127.0.0.1:3001:3001` (not `0.0.0.0`) |
| Web port bound to 127.0.0.1 only | ✅ `127.0.0.1:3000:3000` |

## Functional verification

```
$ cp .env.example .env && docker compose up -d --build
... all images cached from Plan 06; cold first build of compose itself ~25s
$ docker compose ps
postgres   Up 21s (healthy)
redis      Up 21s (healthy)
api        Up 11s (healthy)        127.0.0.1:3001->3001/tcp
web        Up 10s (healthy)        127.0.0.1:3000->3000/tcp
$ curl -s http://localhost:3001/health
{"status":"ok","db":"ok","redis":"ok","timestamp":"2026-04-28T21:18:51.934Z"}
$ curl -sI http://localhost:3000/
HTTP/1.1 200 OK
content-security-policy: default-src 'self'; script-src 'self' 'nonce-...' 'strict-dynamic'; ...
```

**Cold-start (images already built, only volumes/networks fresh):** ~22s wall-time from `up -d` to all-healthy.
**Cold-build-from-scratch (no docker layer cache):** Plan 06 measured ~110s for both images; compose adds <5s on top.

## Networks

- `backend` — `internal: true` (driver: bridge). Members: postgres, redis, api. PG/Redis CANNOT reach the public internet.
- `frontend` — bridge (default, public-egress-capable). Members: api, web. Api is the only service connected to BOTH; pg/redis are isolated.

## `users` table observation

`docker exec ... psql -c '\dt'` returns "no tables". This is **expected** — Plan 06 currently ships only an empty `packages/db/drizzle/meta/_journal.json` placeholder. Plan 08 generates the actual `users` migration (`drizzle-kit generate`) and verifies the migration runs cleanly against PG 18.3. The migrate runner exits cleanly on empty journal so `/health` is green.

## Deviations from plan

1. **Hardening tightened beyond plan.** Plan listed `read_only: false` for api as a TODO; we set `read_only: true` immediately and added `tmpfs: /tmp` per the carry-over note. Web also gets `read_only: true` + tmpfs. Reasoning: cheaper to do once now than in Phase 12, and the security-gate auditor will flag the laxer setting.
2. **Redis pinned to 7.4-alpine** (plan said "any 7.x alpine"). 7.4.x is the current stable line.
3. **No `restart_policy.*` block under deploy:** kept it simple with the YAML anchor `<<: *restart` -> `restart: unless-stopped` (compose-spec). All services restart on failure.
4. **Removed plan's literal `read_only: false` line** from api service (and didn't add it to web).

No Rule-4 deviations; no checkpoints triggered.

## Dokploy mapping (for Plan 10 docs)

In Dokploy's UI for the SimpleVault project, the env-var fields map as:

| `.env.example` key | Dokploy field |
|---|---|
| `DATABASE_URL` | provided automatically by Dokploy's managed Postgres 18.3 service binding |
| `REDIS_URL` | set after creating the Redis service in Dokploy |
| `JWT_SECRET` | encrypted env var (generate via `openssl rand -base64 48`) |
| `SERVER_CHAIN_SECRET` | encrypted env var (generate via `openssl rand -base64 48`) |
| `CORS_ORIGINS` | `https://pass.runadev.com` (no trailing slash) |
| `NEXT_PUBLIC_API_URL` | same-origin via Traefik (`/api` prefix) — final value decided in Phase 14 |
| `NODE_ENV` | `production` |
| `LOG_LEVEL` | `info` |
| `POSTGRES_*` | NOT used in prod — DATABASE_URL replaces them |

## What this unblocks

- **Plan 08** — Drizzle migration generation + PG 18.3 verification: needs the local stack to run `drizzle-kit migrate` against. Compose is ready.
- **Plan 10** — Operator runbook (LOCAL-DEV.md + DOKPLOY-DEPLOY.md): needs the canonical `.env.example` + compose to reference. Both committed.

## Files

- `docker-compose.yml`
- `.env.example`
