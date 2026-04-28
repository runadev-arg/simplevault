# 01-08 Summary — Drizzle migration generation + PG 18.3 verify

**Phase:** 01-foundations
**Plan:** 08
**Wave:** 7
**Date:** 2026-04-28
**Status:** COMPLETE — PG 18.3 + Drizzle stack green-lit

## What shipped

1. **First Drizzle migration generated** from the `users` stub schema:
   - `packages/db/drizzle/0000_talented_microchip.sql` (221 bytes, sha256
     `e58c42df331956ed7ea0b06917533d420d29fd7668452bec18ab06f969bc7793`)
   - `packages/db/drizzle/meta/_journal.json` populated with the entry
   - `packages/db/drizzle/meta/0000_snapshot.json` snapshot file
2. **`drizzle.config.ts` patched** — `schema` field now points at
   `["./src/schema/users.ts"]` instead of the barrel `./src/schema/index.ts`,
   because Drizzle Kit's CJS loader cannot follow our NodeNext `./users.js`
   import in the barrel. New tables must be added explicitly to this list.
3. **PG 18.3 compatibility verified end-to-end** and certified in
   `.planning/phases/01-foundations/01-08-COMPAT.md`:
   - Direct `node ./dist/migrate.js` against PG 18.3 -> migration applied
   - Re-run -> idempotent no-op (journal lookup, no DDL)
   - `docker compose up -d --build api` -> prestart hook runs migration
     on a clean DB, then `Nest application successfully started`
4. **Root `db:*` scripts** added to `package.json` so the operator can run
   `pnpm db:generate`, `pnpm db:migrate`, `pnpm db:studio` from repo root.

## Verified dependency versions (load-bearing)

| Component             | Version       |
|-----------------------|---------------|
| PostgreSQL            | 18.3-alpine   |
| drizzle-orm           | 0.38.4        |
| drizzle-kit           | 0.30.6        |
| pg (node-postgres)    | 8.20.0        |
| Node runtime          | 22-alpine     |

## Commits

- `feat(01-08-T1): generate first drizzle migration (users stub)` -> `126899e`
- `feat(01-08-T2): verify PG 18.3 compatibility end-to-end` -> `9dc28be`
- `chore(01-08-T3): root db:* npm scripts` -> `84bf743`

## Deviations

- **`drizzle.config.ts` schema path** narrowed from `./src/schema/index.ts`
  to `["./src/schema/users.ts"]`. Plan didn't anticipate the NodeNext-vs-CJS
  loader collision. Documented in COMPAT.md and SUMMARY; future tables must
  be appended explicitly.
- **Network-join approach used** (the plan's option B), not the host-port
  override. Skipped the in-container `pnpm install` step from the plan
  because host-side `node_modules` were already populated; bind-mounted
  the repo and ran `node ./dist/migrate.js` directly. No
  `docker-compose.override.yml` was created, so nothing to remove.
- **CHECKPOINT not triggered** — every verification step passed first try.

## Issues / risks for next phase

- None blocking. Drizzle Kit's CJS loader sensitivity is a known footgun
  for future schema additions (see deviation above). Worth a follow-up to
  switch to a glob with an exclusion once a few more tables exist.

## Reference artifacts

- `.planning/phases/01-foundations/01-08-COMPAT.md` — PG 18.3 compatibility
  certificate referenced by `infra-deployment-auditor` at the Phase 14 gate.
- `packages/db/drizzle/0000_talented_microchip.sql` — first migration.
- `packages/db/drizzle/meta/_journal.json` — Drizzle journal (no longer a
  placeholder).
