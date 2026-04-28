# Local development setup

Get a fresh clone from `git clone` to `curl http://localhost:3001/health` returning
`{"status":"ok",...}` in under five minutes.

## Prerequisites

- **Docker + Docker Compose v2** — `docker compose version` should print 2.x
- **Node 22 LTS** — use `nvm use` (the repo has a pinned `.nvmrc`) or your installer's equivalent
- **pnpm 9.15+** — `corepack enable && corepack prepare pnpm@9.15.0 --activate`

## Bring up the full stack (one command)

```bash
git clone <repo-url> simplevault && cd simplevault
cp .env.example .env
pnpm install
docker compose up -d --build
```

Wait ~30 seconds for postgres + redis healthchecks to flip to `healthy`:

```bash
docker compose ps
```

All four services (`postgres`, `redis`, `api`, `web`) should report `running (healthy)`.

### Smoke tests

```bash
# api health
curl -s http://localhost:3001/health | jq
# Expected: {"status":"ok","db":"ok","redis":"ok","timestamp":"..."}

# web is up + CSP nonce is rotating
curl -sI http://localhost:3000/ | grep -i 'content-security-policy'
# Expected: header present with a 'nonce-...' value
```

## Daily dev workflow (hot-reload)

Run only the data services in Docker; run the apps natively for hot-reload:

```bash
docker compose up -d postgres redis
pnpm dev   # turbo runs apps/api on :3001 and apps/web on :3000 with watch
```

> Note: `pnpm dev` reads env vars from your shell. Either `set -a; source .env; set +a`
> before running, or use a tool like `dotenvx`/`direnv`. The compose-up path above
> injects them via `env_file: .env` automatically.

## Database migrations

Drizzle is the source of truth. Pure-SQL output lives in `packages/db/drizzle/`.

```bash
pnpm db:generate   # after editing packages/db/src/schema/* — produces a new SQL file
pnpm db:migrate    # apply pending migrations to $DATABASE_URL
pnpm db:studio     # open Drizzle Studio in the browser
```

In Docker, the api container runs migrations automatically at startup via
`apps/api/scripts/migrate-then-start.sh` (fail-fast on error).

## Useful commands

```bash
pnpm lint           # eslint flat-config across the workspace
pnpm typecheck      # tsc --noEmit everywhere
pnpm build          # turbo build
pnpm test           # turbo test (per-package)
```

## Tear down

```bash
docker compose down           # stop containers, keep volumes (pg_data, redis_data)
docker compose down -v        # also wipe volumes — DESTRUCTIVE
```

## Troubleshooting

- **`api` is `unhealthy`** — usually a migration failure. `docker compose logs api`
  prints the drizzle error. Common cause: stale schema in `pg_data` volume; reset
  with `docker compose down -v`.
- **PG 18.3-specific issues** — see
  [`.planning/phases/01-foundations/01-08-COMPAT.md`](../../.planning/phases/01-foundations/01-08-COMPAT.md)
  for the verification matrix.
- **`web` 500s on first hit** — Next.js may still be JIT-compiling in dev mode; wait
  ~10 seconds and retry. In compose (production build) this never happens.
- **CSP nonce missing** — middleware matcher excludes `_next/static`; only check the
  HTML document URL (`/`).
- **Nuke and pave**:
  ```bash
  docker compose down -v
  pnpm clean 2>/dev/null || rm -rf node_modules apps/*/node_modules packages/*/node_modules .turbo
  pnpm install
  docker compose up -d --build
  ```
