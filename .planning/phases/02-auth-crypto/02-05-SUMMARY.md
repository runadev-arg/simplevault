# 02-05 Summary — DB schema: extend users + add user_sessions + invite_codes

**Phase:** 02-auth-crypto
**Plan:** 05
**Wave:** 2
**Date:** 2026-04-28
**Status:** COMPLETE — schema applied + verified end-to-end on PG 18.3

## What shipped

1. **Three schema files** under `packages/db/src/schema/`:
   - `users.ts` — extended from the Phase 01 stub (3 cols) to 14 columns
   - `user_sessions.ts` — refresh-token rotation lineage
   - `invite_codes.ts` — operator-issued, single-use signup codes
   - `_bytea.ts` — shared Postgres `bytea` <-> `Uint8Array` custom type
2. **Barrel** `schema/index.ts` re-exports all three (and their inferred
   `*Select` / `*Insert` types).
3. **`drizzle.config.ts`** — schema array extended to list all three files
   explicitly (Drizzle Kit CJS-loader limitation per 01-08-COMPAT.md;
   barrel still cannot be used).
4. **Generated migration** `packages/db/drizzle/0001_unusual_moonstone.sql`
   (3571 bytes, sha256
   `c033decad35ae9ef8461ae49037de0936b090151bc55687453425fc54fafe4ba`)
   plus updated `meta/_journal.json` and `meta/0001_snapshot.json`.
5. **End-to-end verification** on PG 18.3-alpine:
   - `node ./dist/migrate.js` against fresh DB -> migrations applied
   - `\dt` confirms 3 tables; `\d` confirms all columns / indexes / FKs
   - Re-run is idempotent (single `begin/commit`, no DDL)
   - `docker compose up -d --build api` runs the prestart hook on a fresh
     volume; api logs show `Migrations applied` -> `Nest application
     successfully started`
   - `docker compose down -v` clean teardown

## Schema — exact column lists (load-bearing for 02-06 / 02-07 / 02-08)

### `users` (post-migration `\d users`)
```
 id                          | uuid                     | not null | gen_random_uuid()
 email                       | text                     | not null |
 created_at                  | timestamp with time zone | not null | now()
 argon2_secret_key_hash      | bytea                    | not null |
 server_argon_salt           | bytea                    | not null |
 argon2_params               | jsonb                    | not null |   -- {memoryKiB,iterations,parallelism}
 user_argon_salt             | bytea                    | not null |
 wrapped_master_dek          | bytea                    | not null |
 wrapped_master_dek_recovery | bytea                    | not null |
 recovery_hmac               | bytea                    | not null |
 user_pub_key                | bytea                    | not null |   -- X25519 (32 B)
 wrapped_user_signing_sk     | bytea                    | not null |   -- Ed25519 (wrapped)
 wrapped_user_kx_sk          | bytea                    | not null |   -- X25519 (wrapped)
 updated_at                  | timestamp with time zone | not null | now()
Indexes:
  users_pkey                  PRIMARY KEY, btree (id)
  users_email_lower_idx       UNIQUE, btree (lower(email))
  users_recovery_hmac_idx     UNIQUE, btree (recovery_hmac)
```

### `user_sessions`
```
 id                 | uuid                     | not null | gen_random_uuid()
 user_id            | uuid                     | not null |
 family_id          | uuid                     | not null |
 refresh_token_hash | bytea                    | not null |   -- BLAKE2b-256 of raw token
 prev_token_id      | uuid                     |          |
 created_at         | timestamp with time zone | not null | now()
 used_at            | timestamp with time zone |          |   -- set on rotation
 revoked_at         | timestamp with time zone |          |   -- set on logout/family-revoke
 user_agent_family  | text                     |          |
 ip_hash            | bytea                    |          |   -- HMAC of client IP
 expires_at         | timestamp with time zone | not null |
Indexes:
  user_sessions_pkey                  PRIMARY KEY, btree (id)
  user_sessions_refresh_hash_idx      UNIQUE, btree (refresh_token_hash)
  user_sessions_user_active_idx       btree (user_id) WHERE revoked_at IS NULL  -- partial
  user_sessions_family_idx            btree (family_id)
FKs:
  user_sessions_user_id_users_id_fk            user_id -> users(id) ON DELETE CASCADE
  user_sessions_prev_token_id_user_sessions_id_fk  prev_token_id -> user_sessions(id) ON DELETE SET NULL
```

### `invite_codes`
```
 id               | uuid                     | not null | gen_random_uuid()
 code_hash        | bytea                    | not null |   -- HMAC(SERVER_INVITE_SECRET, raw_code)
 email            | text                     | not null |   -- lowercased on insert
 created_by       | uuid                     |          |   -- nullable in v1
 created_at       | timestamp with time zone | not null | now()
 expires_at       | timestamp with time zone | not null |
 redeemed_at      | timestamp with time zone |          |
 redeemed_user_id | uuid                     |          |
Indexes:
  invite_codes_pkey                PRIMARY KEY, btree (id)
  invite_codes_code_hash_idx       UNIQUE, btree (code_hash)
  invite_codes_email_lower_idx     btree (lower(email))
  invite_codes_outstanding_idx     btree (expires_at) WHERE redeemed_at IS NULL  -- partial
FKs:
  invite_codes_redeemed_user_id_users_id_fk    redeemed_user_id -> users(id) ON DELETE SET NULL
```

## Truths (from frontmatter — all TRUE)

1. `users` extended with all 11 listed columns + `updated_at` — VERIFIED via
   `\d users`.
2. No column named `master_password`, `password`, `secret_key`,
   `recovery_phrase`, `master_dek`, `kek`, `dek` — VERIFIED via grep over
   `0001_unusual_moonstone.sql` (only `argon2_secret_key_hash` and
   `wrapped_master_dek*` matches, both intentional and documented).
3. `user_sessions` has all 11 listed fields + correct types — VERIFIED.
4. `invite_codes` has all 8 listed fields + correct types — VERIFIED.
5. Migration applies cleanly on PG 18.3 + idempotent re-run is no-op —
   VERIFIED.
6. Schema barrel exports all three tables + inferred types — VERIFIED.

## Server-storage invariant (REQ-CRYPTO-003)

Documented in the `users.ts` module docstring (the SQL columns alone don't
self-document; the doc string is what auditors read alongside `\d users`):

> The server NEVER stores: master password, secret_key, recovery phrase,
> any plaintext KEK or DEK. The only auth-related secret is the verifier
> `argon2_secret_key_hash = Argon2id(secret_key, server_argon_salt,
> argon2_params)`. Login compares the verifier in constant time after a
> timing-floor dummy when the row is absent.

## Verified dependency versions

| Component             | Version       |
|-----------------------|---------------|
| PostgreSQL            | 18.3-alpine   |
| drizzle-orm           | ^0.45.2       |
| drizzle-kit           | ^0.31.10      |
| pg (node-postgres)    | ^8.13.0       |
| Node runtime          | 22-alpine     |

PG 18.3 verdict: **GREEN** — no incompat surfaces. No new SQL features
beyond what was certified in 01-08 (functional and partial indexes are
core PG, not extensions).

## Commits

- `feat(02-05-T1): extend users + add user_sessions + invite_codes schemas`
  -> `0797761`
- `feat(02-05-T2): generate + apply drizzle migration 0001 against PG 18.3`
  -> `f773492`

## Deviations

- **None requiring CHECKPOINT.** One minor in-task fix:
  `user_sessions.ts` initially declared the prev-token self-FK twice (once
  via `.references()` inline, once via an explicit `foreignKey()` block),
  which produced a duplicate FK in the generated SQL. The redundant block
  was removed before the migration was committed. The committed schema +
  SQL contain a single, correctly named FK
  (`user_sessions_prev_token_id_user_sessions_id_fk`).
- **`citext` extension NOT used.** Per the must-haves, lowercase-text +
  `lower(email)` UNIQUE INDEX was chosen for portability. No
  `CREATE EXTENSION` statements in the migration.
- **No hand-edits to generated SQL.** Drizzle Kit emits the
  `lower(email)` functional index correctly when the schema uses the
  `sql\`lower(${t.email})\`` template tag — no need to fall back to
  hand-written SQL.

## Issues / risks for next plans (load-bearing for 02-06 / 02-07 / 02-08)

### Column names + types contract

- **02-06 (CLI invite-code issuance)** must:
  - INSERT into `invite_codes` with: `code_hash` (bytea, HMAC of raw code),
    `email` (lowercased text), `expires_at` (timestamptz, NOT NULL),
    optional `created_by`.
  - Print the raw code to stdout exactly once. NEVER persist it.
  - Use `SERVER_INVITE_SECRET` (new env var — see below) as the HMAC key.

- **02-07 (signup)** must:
  - SELECT `invite_codes` by `code_hash` (constant-time HMAC compare),
    enforce `redeemed_at IS NULL` and `expires_at > now()` and
    `lower(email) = lower($input)`.
  - INSERT into `users` populating ALL 11 new not-null columns from the
    client-side derivation outputs (per CRYPTO-STACK §3 + Plan 02-03 BIP-39
    output): `argon2_secret_key_hash`, `server_argon_salt`,
    `argon2_params`, `user_argon_salt`, `wrapped_master_dek`,
    `wrapped_master_dek_recovery`, `recovery_hmac`, `user_pub_key`,
    `wrapped_user_signing_sk`, `wrapped_user_kx_sk`.
  - UPDATE the redeemed `invite_codes` row: `redeemed_at = now()`,
    `redeemed_user_id = <new user id>`.
  - Email lookups: query with `WHERE lower(email) = lower($1)` to use
    `users_email_lower_idx`.

- **02-08 (login / refresh / logout)** must:
  - Login: SELECT user by `lower(email)`, run Argon2id(secret_key,
    server_argon_salt, argon2_params) and constant-time compare with
    `argon2_secret_key_hash`. On absent row, run a dummy Argon2 with the
    server's default params to floor the timing.
  - On success: INSERT user_sessions row with NEW `family_id` (UUID),
    `refresh_token_hash = blake2b256(rawToken)`, `prev_token_id = NULL`,
    `expires_at = now() + refresh_ttl`.
  - Refresh: SELECT by `refresh_token_hash`. If row.used_at IS NOT NULL ->
    REUSE: `UPDATE user_sessions SET revoked_at = now() WHERE
    family_id = X AND revoked_at IS NULL` (family-revoke). Else: insert new
    row with same `family_id`, set old row's `used_at = now()`.
  - Logout: `UPDATE user_sessions SET revoked_at = now() WHERE
    family_id = X AND revoked_at IS NULL`.

### New env vars surfaced — belong in `.env.example`

The schema introduces three peppers/secrets the server side will need.
**None are added to `.env.example` yet** — Plans 02-06 / 02-07 / 02-08
should each add their own as they consume them, OR a single chore at the
start of 02-06 may add all three together. Listed here so subsequent
executors don't miss them:

| Env var                       | Length      | Used by   | Purpose                                                                       |
|-------------------------------|-------------|-----------|-------------------------------------------------------------------------------|
| `SERVER_INVITE_SECRET`        | 32 bytes    | 02-06, 02-07 | HMAC pepper over raw invite codes -> `invite_codes.code_hash`               |
| `SERVER_RECOVERY_HMAC_SECRET` | 32 bytes    | 02-07, recovery flow (Phase 11) | HMAC pepper for `users.recovery_hmac` lookups       |
| (per-user salts are stored in the row, NOT env vars — `server_argon_salt` and `user_argon_salt` are random per-user)         |

`SERVER_ARGON_SALT` from the carry-over question is **not** an env var — it
is `users.server_argon_salt`, stored per-user in the row (random at signup,
read alongside `argon2_params` at login).

### Other risks

- The migration is destructive in one place: `ALTER TABLE users DROP
  CONSTRAINT users_email_unique`. This is fine because the case-insensitive
  `users_email_lower_idx` (UNIQUE) replaces it and Phase 01 stub had no
  production rows. Document for the threat-modeler so this drop is
  expected.
- 11 NEW NOT NULL columns are added to `users` without DEFAULT. If anyone
  creates rows in the stub `users` between now and signup landing, the
  migration would fail. Verified empty in test runs. Production-safe
  because Phase 02 has no live data yet.
- The partial index `WHERE revoked_at IS NULL` on `user_sessions` will
  bloat over time as logged-out sessions accumulate — partial keeps the
  active-session lookup index small. Phase 10 / runbook should consider a
  periodic vacuum/cleanup of fully-expired rows.

## Reference artifacts

- `packages/db/src/schema/{users,user_sessions,invite_codes,_bytea}.ts`
- `packages/db/src/schema/index.ts` (barrel)
- `packages/db/drizzle.config.ts`
- `packages/db/drizzle/0001_unusual_moonstone.sql`
- `packages/db/drizzle/meta/_journal.json` (idx 1 entry)
- `packages/db/drizzle/meta/0001_snapshot.json`
