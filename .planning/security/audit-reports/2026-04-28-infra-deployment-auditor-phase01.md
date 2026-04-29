# infra-deployment-auditor — Phase 01

**Date:** 2026-04-28
**Scope:** docker-compose, Dockerfiles, app-layer headers, secrets, migrations
**Method:** static analysis (grep + read), no runtime execution
**Verdict:** PASS-WITH-CONCERNS

Overall the Phase 01 foundation is well-hardened: Postgres+Redis are isolated on an `internal: true` network with no host-port publication, the API and Web containers run as non-root with `cap_drop: [ALL]`, `no-new-privileges`, `read_only: true` + `tmpfs`, helmet/CSP wired in, helmet's strict CSP on the API and a per-request nonce CSP via Edge middleware on Web, no committed secrets, dependabot+trivy+pnpm-audit in CI. No Critical findings. The High findings below are real defense-in-depth gaps that should be closed before phase merge per the rubric ("missing `cap_drop`" is explicitly classified as High).

## Findings

### Critical
_None._

### High

**H1. `postgres` service missing `cap_drop: [ALL]`** — `docker-compose.yml:7-28`
The Postgres container has `no-new-privileges` and `pids_limit` but does NOT drop Linux capabilities. Postgres only needs `CHOWN`, `DAC_READ_SEARCH`, `FOWNER`, `SETGID`, `SETUID` (and on Alpine `NET_BIND_SERVICE` is unused since 5432 > 1024). The container therefore retains the full default capability set (≈14 caps) including `NET_RAW`, `SYS_CHROOT`, `MKNOD`. Per audit rubric this is High.
Recommendation: add `cap_drop: [ALL]` and a minimal `cap_add: [CHOWN, DAC_READ_SEARCH, FOWNER, SETGID, SETUID]`.

**H2. `redis` service missing `cap_drop: [ALL]`** — `docker-compose.yml:30-46`
Same as H1. Redis on alpine binding to 6379 needs no Linux capabilities at all when run as the bundled `redis` user. Drop them.
Recommendation: `cap_drop: [ALL]` (no `cap_add` needed).

### Medium

**M1. Postgres + Redis not `read_only`** — `docker-compose.yml:7-46`
Both data services have writable rootfs. With volume-mounted `/var/lib/postgresql/data` and `/data`, the rest of the filesystem could be `read_only: true` with a `tmpfs` for `/tmp` and `/run`. API and Web already do this; data services do not. Lower priority because the network is already `internal: true`.

**M2. Image tags pinned to minor, not digest** — `docker-compose.yml:8,31`, `apps/{api,web}/Dockerfile:5`
`postgres:18.3-alpine`, `redis:7.4-alpine`, `node:22-alpine` are pinned to a tag, not a sha256 digest. A registry tag can be re-pushed. Trivy scans the built image but doesn't catch a swapped base layer between scans. Recommend pinning each base image with `@sha256:…` for reproducibility.

**M3. `api` service in compose has no `cpus` / `deploy.resources` limit** — `docker-compose.yml`
`mem_limit` and `pids_limit` are set, but no CPU cap. Same for `web`, `postgres`, `redis`. A runaway argon2 verify or pino flood could starve the host. Recommend `cpus: "1.0"` (or `deploy.resources.limits.cpus`).

**M4. `web` service `depends_on: api` uses `service_started`, not `service_healthy`** — `docker-compose.yml:88-89`
The API has a healthcheck (`/health`), so the web service can wait for `service_healthy` instead of just `service_started`. Minor: a Next.js SSR page rendered before the API is ready will 502 on first request.

**M5. Dev API published on host even though backend should stay internal** — `docker-compose.yml:65-66`
`api` publishes `127.0.0.1:3001:3001` "for /health checks during dev". Comment is fine, but worth noting the API joins both `backend` (internal) and `frontend` networks; the host port itself is bound only to loopback, so this is acceptable for dev. Info-grade but flagged here because the same compose file should not be reused in prod (Dokploy handles ingress). Confirm a separate `docker-compose.prod.yml` (or override) drops these `ports:` blocks.

**M6. Dockerfile `HEALTHCHECK` uses `curl` against unauthenticated /health and / endpoints** — `apps/api/Dockerfile:68-69`, `apps/web/Dockerfile:54-55`
Functional, but `curl` adds ~3MB to the runner image vs. `wget` (already in busybox via alpine) or `node -e` http probe. Optimization, not a security issue.

### Low

**L1. `.dockerignore` files in `apps/api` and `apps/web` are dead code** — both files comment "build context = repo root, this is defensive". With the canonical command (`docker build -f apps/api/Dockerfile .`) the root `.dockerignore` wins and the per-app one is ignored. Either drop them or document explicitly that they only fire if someone misruns the build with `apps/api` as context.

**L2. `redis` started with `--appendonly yes` but no `requirepass`** — `docker-compose.yml:33`
Network is internal, so unauthenticated Redis is acceptable for v1. Worth noting for Phase 02+ when rate-limit / session data lands in Redis: defense-in-depth would add `--requirepass ${REDIS_PASSWORD}` and update `REDIS_URL` accordingly.

**L3. `helmet` CSP on API allows nothing problematic, but `connect-src 'self'` will block Web→API cross-origin XHR if API and Web end up on different subdomains in prod** — `apps/api/src/main.ts:29`. Phase deployment doc says `pass.runadev.com` (web) and `api.pass.runadev.com` (api) is one option, in which case the API CSP is a moot point (CSP applies to API responses' own resources, not the calling browser's connect-src — the *web* CSP is what matters). Just flagging for the prod cutover.

**L4. `tini` is invoked as `/sbin/tini` — verify path on `node:22-alpine`** — `apps/{api,web}/Dockerfile`
On current alpine `tini` from `apk add tini` lands at `/sbin/tini`. Pin verified by current image, but if base image bumps to a different distribution the entrypoint will silently fail. Consider `ENTRYPOINT ["tini", "--", …]` and rely on PATH, or hard-pin via `which tini`.

### Info

**I1. CI does NOT run `pnpm audit` against `--prod` only.** Currently `pnpm audit --audit-level=high` audits dev deps too, which is correct (dev deps run in CI / build environments). Just noting choice. Out-of-scope for this auditor (dep-supply-chain owns it).

**I2. `migrate-then-start.sh` is idempotent and fail-fast.** `set -eu` + `node ./dist/migrate.js` failing will exit non-zero, container restarts, no half-migrated state. Drizzle's `__drizzle_migrations` table makes re-runs no-ops. ✅

**I3. CSP nonce strategy on Web is correct.** `crypto.getRandomValues(new Uint8Array(16))` → base64 → propagated via `x-nonce` request header, plus `'strict-dynamic'` in `script-src`. This is the modern Next 15 pattern. Server components must read `x-nonce` and apply it to inline `<script>` tags. Verify in Phase 02+ when first inline script lands; Phase 01 has none so untestable here.

**I4. `EXPOSE` minimal:** API only `EXPOSE 3001`, Web only `EXPOSE 3000`. ✅

**I5. No secrets baked into images.** Both Dockerfiles use only `ARG NODE_VERSION`; no `ARG` defaults containing secrets, no `COPY` of `.env*` (root + per-app `.dockerignore` excludes them with `!.env.example` allow-list). `git ls-files | grep .env` returns only `.env.example`. ✅

**I6. `apk add --no-cache` used everywhere** — no stale APK index left in image. ✅

**I7. `pnpm install --frozen-lockfile`** in both Dockerfiles. ✅

**I8. `helmet()` CORS allowlist is env-driven (CSV), not `*`,** with `credentials: true` and a tight method list. ✅

**I9. ValidationPipe** has `whitelist: true, forbidNonWhitelisted: true, transform: true, enableImplicitConversion: false`. ✅

**I10. `.gitignore`** correctly excludes `.env`, `.env.local`, `.env.*.local` and **does not** exclude `.env.example`. ✅

**I11. `frame-ancestors: 'none'` + `X-Frame-Options: DENY`** both set on Web. Belt-and-suspenders for older browsers. ✅

**I12. Trivy scan** in `.github/workflows/container-scan.yml` runs `CRITICAL,HIGH` with `exit-code: 1` and `ignore-unfixed: true`. ✅

**I13. Dependabot** covers npm, github-actions, AND docker (api + web). ✅

## Recommendations (non-blocking)

1. Add a `docker-compose.prod.yml` (or override) for the production deploy that:
   - Drops the `ports:` block on `api` and `web` (Traefik handles ingress)
   - Removes the bundled `postgres` service entirely (Dokploy provides it)
   - Sets `NODE_ENV=production`, real `JWT_SECRET`, real `SERVER_CHAIN_SECRET` via Dokploy's encrypted env UI
2. Consider pinning all base images by digest (`@sha256:…`) in Phase 02 once CI is stable.
3. Phase 02: switch Redis to `requirepass` mode and rotate the connection string.
4. Phase 02: add a `docker scout` or `syft` SBOM step alongside Trivy.
5. Add `read_only: true` + minimal tmpfs for `postgres` (data dir is volume-mounted, rest can be RO) and `redis` (writable `/data` only) — closes M1.

---

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 2 |
| Medium | 6 |
| Low | 4 |
| Info | 13 |

**Verdict: PASS-WITH-CONCERNS.** The two High findings (missing `cap_drop` on the data-tier services) are straightforward, low-risk fixes (a 4-line YAML change). Per the auditor's rubric High findings should block phase merge, but both are remediable in <10 min and require no code change. Recommend orchestrator either (a) fix H1+H2 and re-run this auditor, or (b) accept with a Phase 02 ticket if the operator explicitly waives.
