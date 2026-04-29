# infra-deployment-auditor — Phase 01 RE-RUN

**Date:** 2026-04-29
**Previous verdict:** PASS-WITH-CONCERNS (2 High blocking)
**Re-run scope:** Verification of FINDING-0005 + FINDING-0006 closure + regression check
**Method:** static + brief runtime healthcheck
**Verdict:** PASS

---

## FINDING-0005 closure verification

**Status: VERIFIED-CLOSED.**

`docker-compose.yml:7-36` — `postgres` service now declares:

- `cap_drop: [ALL]` (line 29-30)
- `cap_add: [SETUID, SETGID, DAC_READ_SEARCH, CHOWN, FOWNER]` (line 31-36)
- `security_opt: [no-new-privileges:true]` (line 27-28)

The 5 capabilities retained are exactly the minimal set required by the official `postgres:18.3-alpine` image's initdb path (uid/gid switch from root to `postgres` user, ownership fix-up of the `PGDATA` directory, traversal of the data dir). No extraneous capabilities were added — `NET_RAW`, `SYS_CHROOT`, `MKNOD`, `KILL`, `NET_BIND_SERVICE`, `AUDIT_WRITE`, `SYS_PTRACE` etc. from the default Docker capability set are all dropped. Acceptable.

**Live runtime check:**
```
$ docker compose up -d postgres redis
$ sleep 12 && docker compose ps
simplevault-postgres-1   postgres:18.3-alpine   ...   Up 18 seconds (healthy)   5432/tcp
simplevault-redis-1      redis:7.4-alpine       ...   Up 18 seconds (healthy)   6379/tcp
$ docker compose down -v   # clean
```

Postgres reaches `healthy` with the reduced capability set — initdb completed and `pg_isready` succeeds.

## FINDING-0006 closure verification

**Status: VERIFIED-CLOSED.**

`docker-compose.yml:38-59` — `redis` service now declares:

- `cap_drop: [ALL]` (line 55-56)
- `cap_add: [SETUID, SETGID]` (line 57-59)
- `security_opt: [no-new-privileges:true]` (line 53-54)

`SETUID`+`SETGID` are needed by the official `redis:7.4-alpine` entrypoint to drop from root to the bundled `redis` user before exec'ing `redis-server`. Once dropped, redis-server itself runs unprivileged. No other caps retained — minimal posture confirmed.

**Live runtime check:** Redis container reached `healthy` (`redis-cli ping | grep -q PONG` succeeds) — see live runtime block above.

## Regression check

All other Phase 01 hardening posture re-verified static-only against current HEAD:

| Item | Location | Status |
|---|---|---|
| `postgres` not host-port-published | `docker-compose.yml:17-18` | ✅ networks: [backend] only, no `ports:` block |
| `redis` not host-port-published | `docker-compose.yml:44-45` | ✅ networks: [backend] only, no `ports:` block |
| `backend` network `internal: true` | `docker-compose.yml:120-122` | ✅ unchanged |
| `apps/api/Dockerfile` non-root USER | line 54, 63 | ✅ `addgroup app && adduser -G app`, `USER app` |
| `apps/api/Dockerfile` HEALTHCHECK | line 68-69 | ✅ present |
| `apps/api/Dockerfile` no `:latest` tag | line 5, 8, 52 | ✅ `node:22-alpine` pinned |
| `apps/api/Dockerfile` multi-stage | line 8/29/52 | ✅ deps → build → runner |
| `apps/api/.dockerignore` | present | ✅ |
| `apps/web/Dockerfile` non-root USER | line 39, 52 | ✅ |
| `apps/web/Dockerfile` HEALTHCHECK | line 54-55 | ✅ |
| `apps/web/Dockerfile` no `:latest` | line 5, 8, 37 | ✅ |
| `apps/web/Dockerfile` multi-stage | line 8/28/37 | ✅ |
| `apps/web/.dockerignore` | present | ✅ |
| Strict CSP w/ nonce, no `unsafe-*` | `apps/web/src/middleware.ts` + `apps/web/src/lib/csp.ts` | ✅ no `'unsafe-inline'`, no `'unsafe-eval'`; `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'`; `style-src 'self' 'nonce-${nonce}'`. `next` bumped to `^15.5.15` did not regress nonce flow — Edge middleware still propagates `x-nonce` request header and stamps response CSP. |
| API helmet + CORS allowlist + ValidationPipe | `apps/api/src/main.ts:18-58` | ✅ helmet CSP/HSTS/referrerPolicy intact; CORS env-driven allowlist with `credentials: true`, methods locked; ValidationPipe `whitelist + forbidNonWhitelisted + transform + enableImplicitConversion: false` |
| `migrate-then-start.sh` fail-fast | `apps/api/scripts/migrate-then-start.sh:6` | ✅ `set -eu` + `node ./dist/migrate.js` (any non-zero aborts; container restarts on next pull) |

**No regressions detected.** Dependency bumps (`next ^15.5.15`, multer override per FINDING-0004) and compose edits (cap_drop/add, no-new-privileges) did not weaken any prior posture.

## New findings (if any)

_None._ The capability lists added in `579ea8d` are minimal-and-justified; no new attack surface introduced.

## Carried-over Medium/Low/Info from 2026-04-28 run

All carried over, **unchanged** (none became worse, none became better unless noted):

- M1. Postgres + Redis not `read_only` — carried over.
- M2. Image tags pinned to minor, not digest — carried over.
- M3. No `cpus` / `deploy.resources` limit — carried over.
- M4. `web depends_on api` uses `service_started` — carried over.
- M5. Dev API published on host (loopback only) — carried over; reminder a separate prod compose override is still required.
- M6. HEALTHCHECK uses `curl` — carried over (cosmetic).
- L1. Per-app `.dockerignore` files — carried over.
- L2. Redis no `requirepass` — carried over (Phase 02 ticket).
- L3. API CSP `connect-src 'self'` semantics in cross-subdomain prod — carried over.
- L4. `tini` path hardcoded `/sbin/tini` — carried over.
- I1–I13. All thirteen Info items still hold; specifically I2 (migrate-then-start fail-fast), I3 (CSP nonce strategy), I8 (CORS allowlist), I9 (ValidationPipe), I10 (.gitignore), I11 (frame-ancestors), I12 (Trivy CRITICAL,HIGH exit-code 1), I13 (Dependabot npm+actions+docker) re-verified.

---

## Summary

| Severity | Previous (2026-04-28) | Now (2026-04-29) |
|---|---|---|
| Critical | 0 | 0 |
| High | 2 | 0 |
| Medium | 6 | 6 (carried) |
| Low | 4 | 4 (carried) |
| Info | 13 | 13 (carried) |

**Verdict: PASS.** Both blocking High findings are closed with minimal-and-justified capability sets, `no-new-privileges` is in place on both data services, and the rest of the Phase 01 hardening posture is intact. Containers verified healthy under the new posture. Phase 01 gate may proceed.
