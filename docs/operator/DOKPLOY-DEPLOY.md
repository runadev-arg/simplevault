# Production deploy with Dokploy

Operator runbook for deploying SimpleVault to a Dokploy-managed VPS at
`pass.runadev.com`. Phase 01 makes the repo *deployable*; the actual go-live
ceremony is owned by Phase 14 — this document is the input to that ceremony.

> **Critical mistake to avoid:** when you create the Dokploy apps, set the
> **build context** to the **repo root** (`.`), NOT to `apps/api/` or `apps/web/`.
> The Dockerfiles `COPY` workspace packages from outside their own app directory;
> a per-app build context will fail with `not found` errors during install.

## Prerequisites (operator)

- A Dokploy instance running on your VPS, healthy and reachable.
- A managed Postgres 18.3 instance created in Dokploy (suggested name:
  `pg_simplevault`). Grab its internal connection string from the Dokploy UI.
- An A record for `pass.runadev.com` pointing at the VPS public IP. Traefik
  (Dokploy-managed) will provision Let's Encrypt automatically once the app is
  deployed and a domain is attached.
- (Phase 02+) An SMTP provider (or self-hosted relay) for transactional email.
  Not needed for Phase 01.

## One-time Dokploy setup

### 1. Create a Redis service

Dokploy → **Add Service** → **Redis**. Name: `redis_simplevault`.
Note the internal connection URL Dokploy reports — typically
`redis://redis_simplevault:6379`.

This is a fresh Redis dedicated to SimpleVault. Do not reuse a Redis serving
other apps (rate-limit + session keys would collide).

### 2. Create the **api** app

| Field | Value |
|---|---|
| **Name** | `simplevault-api` |
| **Source** | Git (this repo) |
| **Build type** | Dockerfile |
| **Build context** | `.` (repo root — **NOT** `apps/api/`) |
| **Dockerfile path** | `apps/api/Dockerfile` |
| **Internal port** | `3001` |
| **Healthcheck** | `GET /health` (Dockerfile already declares HEALTHCHECK; Dokploy auto-detects) |
| **Domain** | internal-only by default. If you want it externally addressable for debugging, attach `api.pass.runadev.com` and set Force HTTPS ON. Recommend internal-only for prod. |

### 3. Create the **web** app

| Field | Value |
|---|---|
| **Name** | `simplevault-web` |
| **Source** | Git (same repo) |
| **Build type** | Dockerfile |
| **Build context** | `.` (repo root) |
| **Dockerfile path** | `apps/web/Dockerfile` |
| **Internal port** | `3000` |
| **Domain** | `pass.runadev.com` |
| **Force HTTPS** | ON (Traefik will provision Let's Encrypt automatically) |

> Apps do **not** need host port mappings in production. Traefik (Dokploy-managed)
> handles TLS termination and routing. The `apps/web` container already runs with
> `HOSTNAME=0.0.0.0` so Traefik can reach it on the internal Docker network.

### 4. Environment variables (Dokploy encrypted env-var UI)

Set via Dokploy's **Environment** tab on each app. **Never put production
secrets in `.env` files committed to git** — `.env.example` lives at the repo
root for reference only.

The full mapping derives from `turbo.json`'s `passThroughEnv` and the
`.env.example` documentation (see Plan 07 SUMMARY for the canonical table).

**`simplevault-api`:**

| Name | Value |
|---|---|
| `NODE_ENV` | `production` |
| `PORT` | `3001` |
| `DATABASE_URL` | Copy from Dokploy Postgres service details panel (internal URL) |
| `REDIS_URL` | `redis://redis_simplevault:6379` |
| `JWT_SECRET` | `openssl rand -base64 48` — generate fresh; **store an offline copy** for disaster recovery |
| `SERVER_CHAIN_SECRET` | `openssl rand -base64 48` — generate fresh; **CRITICAL** — losing this breaks the audit hash chain (see SECURITY-NOTES.md) |
| `CORS_ORIGINS` | `https://pass.runadev.com` |
| `LOG_LEVEL` | `info` |

**`simplevault-web`:**

| Name | Value |
|---|---|
| `NODE_ENV` | `production` |
| `PORT` | `3000` |
| `HOSTNAME` | `0.0.0.0` |
| `NEXT_PUBLIC_API_URL` | Either `https://pass.runadev.com/api` (if you set up a Traefik subpath route to api) or the internal Dokploy network URL of the api service. **Phase 12 finalizes this** — for Phase 01 the value only matters for smoke tests. |

### 5. Networking

In Dokploy, ensure both apps + Postgres + Redis sit on the same internal
Docker network. **Postgres must NOT be exposed externally** — only the api app
needs to reach it. Redis likewise: internal-only.

Application security headers (HSTS, CSP, COOP, CORP, Permissions-Policy) are
emitted by the app layer (Next.js middleware + NestJS helmet). **Do not
configure header rules in Traefik** — they would either duplicate or conflict.

### 6. Deploy

- If you enabled **auto-deploy on push to `main`**: pushing to `main` triggers
  a build + redeploy.
- Manual: hit **Deploy** in the Dokploy UI for each app.

The api container's entrypoint (`apps/api/scripts/migrate-then-start.sh`) runs
`drizzle-kit migrate` against `DATABASE_URL` before booting Nest. If the
migration fails, the container exits non-zero and Dokploy marks the deploy
failed — atomic, fail-fast (this is the desired behavior). PG 18.3 + Drizzle
compatibility is verified end-to-end in
[`.planning/phases/01-foundations/01-08-COMPAT.md`](../../.planning/phases/01-foundations/01-08-COMPAT.md).

## Verifying a deploy

```bash
# TLS + security headers from Traefik + app middleware
curl -sI https://pass.runadev.com/ | grep -iE 'strict-transport|content-security|x-frame|referrer-policy'

# api /health (only if you exposed api at api.pass.runadev.com)
curl -s https://api.pass.runadev.com/health
# Expected: {"status":"ok","db":"ok","redis":"ok","timestamp":"..."}
```

## Backups

Off-site logical backups (`pg_dump` over rsync over SSH to operator-owned
VPS/NAS) are wired up in Phase 14. **The operator must provide the backup
target host + SSH credentials before Phase 14** — see
[`SECURITY-NOTES.md`](./SECURITY-NOTES.md).

VPS-level snapshots from your hosting provider are a useful second line of
defense, but **do not replace** logical `pg_dump` backups (a corrupted
filesystem snapshot can lose data identically; logical dumps survive).

## Rollback

Dokploy keeps prior deploys; click **Redeploy previous version** in the UI.

> **Caveat:** if a deploy applied a forward-only schema migration that the
> previous container image doesn't know about, naive rollback may produce
> runtime errors. Phase 14 documents the expand/contract migration discipline
> that prevents this. Until then: any rollback that crosses a migration
> boundary requires a manual SQL undo.

## CODEOWNERS reminder

`.github/CODEOWNERS` uses `@germankatz` as the sole owner. **Operator: confirm
this matches your actual GitHub username.** If not, edit `CODEOWNERS` and
re-push before inviting collaborators or enabling required reviews.
