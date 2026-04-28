# PG 18.3 + Drizzle Compatibility Certificate

**Phase:** 01-foundations
**Plan:** 08
**Date:** 2026-04-28
**Verdict:** GREEN — PG 18.3 + Drizzle stack verified end-to-end.

## Verified dependency versions

| Component             | Version (locked) | Source                          |
|-----------------------|------------------|---------------------------------|
| PostgreSQL            | 18.3 (alpine)    | `postgres:18.3-alpine` image    |
| drizzle-orm           | 0.38.4           | `packages/db/package.json`      |
| drizzle-kit           | 0.30.6           | `packages/db/package.json`      |
| pg (node-postgres)    | 8.20.0           | resolved from `^8.13.0`         |
| Node.js (runtime)     | 22-alpine        | `node:22-alpine` image          |

PG server `SELECT version()`:
`PostgreSQL 18.3 on aarch64-unknown-linux-musl, compiled by gcc (Alpine 15.2.0) 15.2.0, 64-bit`

## Verified behaviors

1. **`drizzle-kit generate` works** against the users-stub schema and emits
   `packages/db/drizzle/0000_talented_microchip.sql`
   (sha256 `e58c42df331956ed7ea0b06917533d420d29fd7668452bec18ab06f969bc7793`,
   221 bytes).
2. **First-time migration applies cleanly** to PG 18.3 via
   `node ./dist/migrate.js`. `drizzle.__drizzle_migrations` and `public.users`
   are created in a single transaction.
3. **Idempotent re-run** is a no-op — the second `migrate.js` invocation
   exits 0 with `[migrate] Migrations applied` and emits no DDL queries
   beyond the journal lookup.
4. **API container prestart hook** (`apps/api/scripts/migrate-then-start.sh`)
   runs the same migration on a clean database and proceeds to `Nest
   application successfully started` in <100ms after migrations applied.

## Generated SQL

```sql
CREATE TABLE "users" (
        "id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
        "email" text NOT NULL,
        "created_at" timestamp with time zone DEFAULT now() NOT NULL,
        CONSTRAINT "users_email_unique" UNIQUE("email")
);
```

Nothing in this DDL trips on a PG 18.x change:
- `gen_random_uuid()` is core (was promoted from pgcrypto extension to core
  in PG 13; available in 18 without extension load).
- `timestamp with time zone` is unchanged.
- The `__drizzle_migrations` table uses `SERIAL` and `bigint` — both still
  supported in 18.

## Deviations from plan

- `drizzle.config.ts` `schema` field was changed from `./src/schema/index.ts`
  to `["./src/schema/users.ts"]`. Reason: drizzle-kit's CJS loader could not
  resolve our NodeNext `./users.js` import in the barrel `index.ts`. Pointing
  at the per-table file directly bypasses the barrel. **Action item:** when
  new tables are added, list them explicitly in the `schema` array (or
  switch to a glob that excludes `index.ts`).
- The plan suggested either a host-port override or a one-shot installer
  container. Neither was needed: the host already had `node_modules`
  installed by pnpm, so a plain `node:22-alpine` container with `--network
  simplevault_backend` and the repo bind-mounted ran `dist/migrate.js`
  directly. No `docker-compose.override.yml` was created.

## Reference for `infra-deployment-auditor`

Treat this certificate as the green-light for shipping PG 18.3-alpine to
Dokploy. If a future Drizzle Kit / drizzle-orm bump regresses on PG 18,
re-run all four checks above before merging.
