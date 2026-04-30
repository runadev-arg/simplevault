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

| Name | Required | Format | Notes |
|---|---|---|---|
| `NODE_ENV` | yes | `production` | |
| `PORT` | yes | `3001` | |
| `DATABASE_URL` | yes | Postgres URL | Copy from Dokploy Postgres service details panel (internal URL). |
| `REDIS_URL` | yes | Redis URL | `redis://redis_simplevault:6379` |
| `JWT_SECRET` | yes | ≥32 B random | `openssl rand -base64 48` — store an offline copy for disaster recovery. Min 32 bytes; the api fails fast on shorter values. |
| `SERVER_INVITE_SECRET` | yes | ≥32 B random | `openssl rand -base64 32` — peppers the HMAC over invite codes so a DB-only compromise can't enumerate raw codes. Used by `pnpm cli invite create` AND `POST /invite/redeem`. |
| `SERVER_RECOVERY_HMAC_SECRET` | yes | ≥32 B random | `openssl rand -base64 32` — outer HMAC over `sha256(recovery_phrase)` so a DB-only compromise can't precompute lookups. |
| `SERVER_ARGON_SALT` | yes | 16 B random base64 | `openssl rand -base64 16` — global server-side salt mixed into every Argon2id verifier. Public-by-convention pepper (security depends on the user's 128-bit `secret_key`); does NOT need to be kept private once issued, but MUST be stable for the lifetime of the deployment. |
| `SERVER_IP_HASH_SECRET` | yes | ≥32 B random | `openssl rand -base64 32` — keyed-HMAC of client IPs in `user_sessions` + audit events so a DB dump doesn't yield raw IPs. |
| `SERVER_CHAIN_SECRET` | yes | ≥32 B random | `openssl rand -base64 48` — Phase-10 audit-chain HMAC. **CRITICAL** — losing this breaks the audit hash chain (see SECURITY-NOTES.md). Do NOT rotate without the audit-chain re-bootstrap ceremony. |
| `ACCESS_TOKEN_TTL` | optional | seconds | Default `900` (15 min). Shorter = more refresh churn; longer = bigger blast-radius on token theft. |
| `REFRESH_TOKEN_TTL` | optional | seconds | Default `2592000` (30 days). Per REQ-AUTH-002. |
| `ARGON2_MEMORY_KIB` | yes for prod | integer (KiB) | Operator runs `pnpm cli argon2 calibrate` ON THE VPS to set; default `65536` (64 MiB). See SECURITY-NOTES.md. |
| `ARGON2_ITERATIONS` | yes for prod | integer | default `3`. |
| `ARGON2_PARALLELISM` | yes for prod | integer | always `1` for libsodium WASM. |
| `LOGIN_IP_RATE_LIMIT` | optional | integer/window | Default 5/IP/15min (REQ-RATELIMIT-002). |
| `LOGIN_EMAIL_RATE_LIMIT` | optional | integer/window | Default 10/email/15min. |
| `SIGNUP_IP_RATE_LIMIT` | optional | integer/window | Default 3/IP/hour (REQ-RATELIMIT-003). |
| `REFRESH_IP_RATE_LIMIT` | optional | integer/window | Default 30/IP/15min. |
| `INVITE_REDEEM_IP_RATE_LIMIT` | optional | integer/window | Default 10/IP/hour. |
| `CORS_ORIGINS` | yes | comma-separated | `https://pass.runadev.com` |
| `LOG_LEVEL` | optional | `info`/`warn`/`error` | Default `info`. |

**`simplevault-web`:**

| Name | Value |
|---|---|
| `NODE_ENV` | `production` |
| `PORT` | `3000` |
| `HOSTNAME` | `0.0.0.0` |
| `NEXT_PUBLIC_API_URL` | **LEAVE UNSET** in production. Web + api MUST share an origin (`https://pass.runadev.com/api/*` → api, everything else → web) — see "Same-origin requirement" below. With same-origin, the browser-side auth client falls back to relative URLs and the `__Host-refresh` cookie rides on every same-origin request. **Only set this in dev** (e.g. `http://localhost:3001`). |

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

### 7. Same-origin requirement (LOAD-BEARING)

The refresh-token cookie is named `__Host-refresh`. Per the
[`__Host-` cookie prefix spec](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-the-__host-prefix), it MUST have:

- `Path=/`
- `Secure`
- **No `Domain` attribute**

That last point means the cookie is bound to the **exact origin** that
set it. So **web and api MUST be served from the same origin**.

**Configure Traefik in Dokploy** (path-routing under `pass.runadev.com`):

- `pass.runadev.com/api/*` → `simplevault-api:3001` (strip the `/api`
  prefix or configure NestJS's `app.setGlobalPrefix('api')` — the
  api code already supports either via `API_PATH_PREFIX`).
- `pass.runadev.com/*` (everything else) → `simplevault-web:3000`.

The Dokploy UI surfaces this as Traefik labels on the api app, e.g.:

```
traefik.http.routers.simplevault-api.rule=Host(`pass.runadev.com`) && PathPrefix(`/api`)
traefik.http.middlewares.api-strip.stripprefix.prefixes=/api
traefik.http.routers.simplevault-api.middlewares=api-strip@docker
```

**Do NOT** put the api on a separate subdomain (`pass-api.runadev.com`)
— the `__Host-` cookie cannot transit between subdomains, and login
will silently break after the next refresh window.

If you need per-tenant subdomains in the future (`alice.pass.runadev.com`),
the `__Host-` prefix is incompatible. Phase 13 hardening pass tracks the
migration path (drop `__Host-`, switch to `__Secure-` + explicit `Domain`,
or move the refresh cookie behind a same-site service worker).

### 8. Pre-cutover checklist

Before flipping DNS or marking the deploy live, the operator MUST:

- [ ] **Generate the four crypto secrets** via `openssl rand`:
  - `JWT_SECRET` — `openssl rand -base64 48`
  - `SERVER_INVITE_SECRET` — `openssl rand -base64 32`
  - `SERVER_RECOVERY_HMAC_SECRET` — `openssl rand -base64 32`
  - `SERVER_IP_HASH_SECRET` — `openssl rand -base64 32`
  - `SERVER_CHAIN_SECRET` — `openssl rand -base64 48` (Phase-10 critical)
  - `SERVER_ARGON_SALT` — `openssl rand -base64 16`
  Paste each into Dokploy's encrypted env-var UI for `simplevault-api`.
  **Store an offline copy** of `SERVER_CHAIN_SECRET` (encrypted USB / safe).
- [ ] **Run `pnpm cli argon2 calibrate` on the VPS** (or `docker exec
  -it <api-container> simplevault-cli argon2 calibrate`). Paste the
  three printed values (`ARGON2_MEMORY_KIB`, `ARGON2_ITERATIONS`,
  `ARGON2_PARALLELISM`) into the api env. See SECURITY-NOTES.md.
- [ ] **Verify Traefik routes** `pass.runadev.com/api/*` to api and
  `pass.runadev.com/*` to web — `curl -sI https://pass.runadev.com/api/health`
  returns 200 and `curl -sI https://pass.runadev.com/login` returns
  200 with the web's HTML.
- [ ] **Issue the first operator invite**:
  ```bash
  docker exec -it <api-container> simplevault-cli invite create --email <operator-email>
  ```
  Capture the printed code (single OOB delivery — there is no SMTP in
  v1; deliver to yourself via Signal / your own email client / paper).
- [ ] **Walk the signup wizard** at `https://pass.runadev.com/signup` end
  to end with the operator email + a strong master password + the
  generated secret_key + recovery phrase. Print/store the Recovery Kit
  before clicking through.
- [ ] **Verify auto-refresh** — leave the `/me` tab open longer than
  `ACCESS_TOKEN_TTL` and watch DevTools network for one transparent
  `POST /auth/refresh` 200.
- [ ] **Verify logout** — click logout, confirm the `__Host-refresh`
  cookie is gone in DevTools and `/me` redirects to `/login`.

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

## Operator CLI reference

Phase 02 ships an operator-only CLI (workspace `@simplevault/cli`,
binary `simplevault-cli`) with two subcommands. Invoke it from inside
the api container (which has the same env vars) or from a dev checkout
on the host with `DATABASE_URL` + `SERVER_INVITE_SECRET` set.

### `invite create`

Issues a single-use, HMAC-bound invite code with a default 7-day TTL.

```bash
simplevault-cli invite create --email user@example.com [--ttl-days 7]
```

- Generates 16 random bytes → Crockford-base32 (26 chars) → hyphenated
  (e.g. `K3JM-9PXQ-7T4N-22HS-VR8E-A6YF`).
- Stores `HMAC-SHA256(SERVER_INVITE_SECRET, raw_code)` in
  `invite_codes.code_hash` (DB-only compromise can't enumerate raw
  codes).
- Prints the raw code to stdout **once** — deliver out-of-band (Signal,
  in-person, your own email client). v1 has no SMTP integration; that's
  Phase 07.
- The `email` field is a **binding identifier**, not a delivery target —
  signup will fail if the redeemer's email doesn't match.

### `argon2 calibrate`

One-time per-host calibration of Argon2id memory + iteration cost.

```bash
simplevault-cli argon2 calibrate
```

- Targets ~750 ms wall time per derivation (CRYPTO-STACK §2).
- Prints three env-var lines (`ARGON2_MEMORY_KIB=…`,
  `ARGON2_ITERATIONS=…`, `ARGON2_PARALLELISM=1`).
- Paste into Dokploy's api env-var UI and redeploy. See
  [`SECURITY-NOTES.md`](./SECURITY-NOTES.md) for the full procedure.

## CODEOWNERS reminder

`.github/CODEOWNERS` uses `@germankatz` as the sole owner. **Operator: confirm
this matches your actual GitHub username.** If not, edit `CODEOWNERS` and
re-push before inviting collaborators or enabling required reviews.
