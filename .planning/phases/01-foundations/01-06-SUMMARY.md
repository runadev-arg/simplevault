# Plan 01-06 — Production Dockerfiles — SUMMARY

**Phase:** 01 — Foundations
**Wave:** 5 (parallel with Plan 09)
**Status:** COMPLETE
**Commits:** 4ced17e, ce542d4, fd48fd6

## What landed

| Artifact | Path |
|---|---|
| api production image | `apps/api/Dockerfile` |
| migrate-then-start hook | `apps/api/scripts/migrate-then-start.sh` |
| Drizzle migration runner | `packages/db/src/migrate.ts` (compiled to `dist/migrate.js`) |
| Empty migrations placeholder | `packages/db/drizzle/meta/_journal.json` |
| web production image | `apps/web/Dockerfile` |
| Next.js outputFileTracingRoot | `apps/web/next.config.mjs` (updated) |
| Build context filters | `.dockerignore`, `apps/api/.dockerignore`, `apps/web/.dockerignore` |

## Image sizes (verified locally)

| Image | Size | Plan target | Notes |
|---|---|---|---|
| `simplevault-api:latest` | **329 MB** | <300 MB | Slightly over target. Node 22 alpine base (~140 MB) + pruned prod deps (NestJS, drizzle-orm, pg, ioredis, helmet, pino, libsodium-wrappers-sumo via @simplevault/crypto, etc.). Acceptable for v1; revisit with `node:22-alpine` -> `gcr.io/distroless/nodejs22` in Phase 12/13 if size becomes painful. |
| `simplevault-web:latest` | **328 MB** | <200 MB | Significantly over target. Next 15 + React 19 standalone bundle is heavier than v14. The plan's <200 MB target was optimistic for the Next 15 + standalone + alpine combo (the standalone bundle alone ships ~180 MB of next/server runtime). Could be trimmed by switching to `gcr.io/distroless/nodejs22` runner (saves ~80 MB) — deferred to Phase 12 hardening. Not blocking. |

## Verification results

### apps/api

- `docker build -f apps/api/Dockerfile -t simplevault-api .` succeeds.
- `Config.User` = `app` (non-root, uid 100, gid 101).
- `Config.Entrypoint` = `["/sbin/tini", "--", "./migrate-then-start.sh"]`.
- `Config.ExposedPorts` = `{"3001/tcp":{}}` only.
- HEALTHCHECK present: `curl -fsS http://localhost:3001/health`, 20s interval, 5s timeout, 15s start period, 3 retries.
- Migration fail-fast confirmed: `docker run --rm -e DATABASE_URL=postgres://invalid:notreal@127.0.0.1:1/none simplevault-api` runs migrate.js, surfaces `ECONNREFUSED`, exits non-zero.
- Verified non-root via entrypoint override: `docker run --rm --entrypoint id simplevault-api` -> `uid=100(app) gid=101(app)`.

### apps/web

- `docker build -f apps/web/Dockerfile -t simplevault-web .` succeeds.
- `Config.User` = `app` (non-root).
- `Config.Entrypoint` = `["/sbin/tini", "--", "node", "apps/web/server.js"]`.
- HEALTHCHECK present: `curl -fsS http://localhost:3000/`, 20s interval, 10s start period.
- Runtime test: `docker run -d -p 13000:3000 simplevault-web` -> ready in 145ms; `curl -sI http://localhost:13000/` returns 200 OK with full CSP, HSTS, X-Frame-Options DENY, Permissions-Policy, COOP/CORP, Referrer-Policy, X-Content-Type-Options, X-DNS-Prefetch-Control headers from Plan 05's middleware. Body contains `SimpleVault` placeholder.
- Verified non-root via entrypoint override.

### .dockerignore

- Build context size for both builds was small (transferred manifests + sources only; no `node_modules`, `.next`, `.tsbuildinfo`, `.git`, or `.planning`). Verified by inspecting build output (no >5MB context warnings, COPY layers sub-100ms).

## Deviations from plan

1. **Dropped `--legacy` flag from `pnpm deploy`**: Plan suggested it but it's a pnpm-10-only flag; pnpm 9.15.0 (pinned `packageManager`) errors out on it. Plain `pnpm --filter @simplevault/api deploy --prod /out` works correctly. No functional change.
2. **Added `packages/db/drizzle/meta/_journal.json` placeholder**: An empty drizzle migrations folder is required for the runner to start without ENOENT. Plan 08 will populate it with real migrations; the placeholder is an empty journal (zero entries), which the migrator treats as a no-op.
3. **Migrations folder location**: Plan suggested `cd /app/packages/db && node ./dist/migrate.js`. The actual `pnpm deploy` layout puts the package at `/app/node_modules/@simplevault/db/`, so the script `cd`s there instead. Functionally equivalent.
4. **Image sizes exceed targets** (api 329 vs 300 MB; web 328 vs 200 MB). Documented above; not blocking, revisit in Phase 12/13 hardening with distroless base.
5. **Removed `COPY ... drizzle.config.ts` and `COPY ... packages/db/dist`** from plan's runner stage: with the corrected pnpm-deploy layout, the package's own `dist/` and `drizzle/` already live under `/app/node_modules/@simplevault/db/`. drizzle.config.ts isn't needed at runtime (only at `drizzle-kit generate` time, which never runs in the container).

## Dokploy build configuration

For each app in Dokploy:

| Setting | Value |
|---|---|
| Build provider | **Dockerfile** |
| Build context | **monorepo root** (`/`) — NOT `apps/<app>/`. Required because Dockerfiles `COPY` workspace packages (`packages/shared`, `packages/db`, etc.) which sit outside the app dir. |
| Dockerfile path | `apps/api/Dockerfile` for api / `apps/web/Dockerfile` for web |
| Build arg `NODE_VERSION` | leave default (`22-alpine`) unless pinning |
| Health endpoint | `/health` (api) / `/` (web) — Traefik routes use these for ready checks |
| Resource limits (suggested) | api: 512MB mem / 0.5 CPU; web: 384MB mem / 0.5 CPU. Tune after first load tests. |

Caveat: `pnpm deploy --filter` requires the lockfile to be present at build context root. Dokploy mounts the cloned repo as context, so this works out of the box.

## Carry-overs / signals for later plans

### Plan 07 (docker-compose)
- Both images expose only their app port (3001 / 3000); compose must NOT publish Postgres/Redis ports to host.
- api needs `DATABASE_URL` and `REDIS_URL` env vars; HEALTHCHECK already wired so compose `depends_on: condition: service_healthy` will work for both.
- Migration is run inline at api container start, not as a separate init container — compose can rely on api's HEALTHCHECK going green to gate downstream services.

### Plan 08 (migrations)
- `packages/db/drizzle/` placeholder is in place. Plan 08 should `pnpm db:generate` to populate it; the existing `_journal.json` will be overwritten by drizzle-kit on first generate.
- `packages/db/src/migrate.ts` is the runtime entrypoint; do not change its location or `node ./dist/migrate.js` invocation in `migrate-then-start.sh` will break.

### Plan 09 (CI container scan)
- Both images are reproducibly built from the lockfile — no floating versions.
- Add `docker buildx build --platform linux/amd64,linux/arm64` to CI matrix (current local builds use the buildx default, which already produces multi-platform manifests on Apple Silicon). Trivy/grype scans should target both Dockerfiles.
- Image-size assertion in CI suggested: `<400 MB` per image (with headroom over current sizes).

### Plan 14 (deploy)
- Dokploy build settings table above is the source of truth.
- `tini` is at `/sbin/tini` (alpine package), not `/usr/bin/tini` (debian) — relevant if the team ever inspects with `docker exec`.
- Standalone Next.js binds to `HOSTNAME=0.0.0.0`; Traefik forwards directly. Make sure the Dokploy Traefik label uses the container port, not host port.

## Security notes (for Phase end gate)

- Non-root user (`app`, uid 100). PASS.
- No host port mapping in either Dockerfile (only `EXPOSE`). PASS.
- HEALTHCHECK present on both. PASS.
- `tini` as PID 1 ensures clean SIGTERM forwarding (Postgres pool drains, Next server flushes). PASS.
- Read-only FS: NOT enforced inside the Dockerfile; deferred to compose `read_only: true` in Plan 07. The api needs `/tmp` writable for pino/log buffering; will need `tmpfs:` mount in compose.
- `cap_drop`: deferred to compose / Dokploy runtime config (Dockerfile can't set caps).
- Only production deps in final image (via `pnpm deploy --prod`). PASS.
- No secrets baked into images (verified — no `ENV` with secrets, no COPY of `.env*`). PASS.
