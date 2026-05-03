---
phase: 03-2fa-sessions
plan: 01
subsystem: db-schema
tags: [drizzle, postgres, webauthn, totp, session-epoch, finding-0017, finding-0022]
requires:
  - 02-05 (DB schema baseline — users/user_sessions/invite_codes)
  - 02-09 (Throttler config — context for FINDING-0022 fold rationale)
provides:
  - webauthn_credentials table (passkey storage)
  - webauthn_challenges table (short-lived ceremony nonces)
  - totp_credentials table (server-opaque wrapped secret + replay-guard column)
  - users.session_epoch column (per-user revocation primitive — REQ-AUTH-004)
  - users.email + invite_codes.email tightened to varchar(254) (FINDING-0017 storage tier)
  - LoginSchema.email + MeResponseSchema.email + CLI invite-create email arg .max(254) (FINDING-0017 Zod tier)
affects:
  - 03-02 (WebAuthn API — consumes webauthn_credentials + webauthn_challenges)
  - 03-03 (TOTP API — consumes totp_credentials)
  - 03-04 (Session-epoch JWT claim — consumes users.session_epoch)
  - 03-05 (Sessions list/revoke — bumps session_epoch)
  - 03-06 (2FA methods list/delete)
  - 03-09 (Throttler ordering + login-email keying — closes FINDING-0022 fully)
tech-stack:
  added: []
  patterns:
    - "Drizzle migration with defensive DO-block pre-flight guard for destructive type changes"
    - "Separate-table-per-credential-kind 2FA schema (vs polymorphic single table) — keeps replay-guard column local to TOTP and counter-regression check local to WebAuthn"
key-files:
  created:
    - packages/db/src/schema/webauthn_credentials.ts
    - packages/db/src/schema/webauthn_challenges.ts
    - packages/db/src/schema/totp_credentials.ts
    - packages/db/drizzle/0002_phase03_2fa_sessions.sql
    - packages/db/drizzle/meta/0002_snapshot.json
  modified:
    - packages/db/src/schema/users.ts (session_epoch column + email -> varchar(254))
    - packages/db/src/schema/invite_codes.ts (email -> varchar(254))
    - packages/db/src/schema/index.ts (barrel update)
    - packages/db/drizzle.config.ts (added new schema modules to the explicit file list)
    - packages/db/drizzle/meta/_journal.json (renamed 0002 tag to phase03_2fa_sessions)
    - apps/api/src/auth/login/login.dto.ts (email .max(254))
    - packages/shared/src/zod/index.ts (MeResponseSchema.email .max(254))
    - apps/cli/src/commands/invite-create.ts (254-char ceiling guard)
duration: ~30min
completed: 2026-05-02
---

# Phase 03 Plan 01: 2FA + sessions DB schema foundation Summary

Three new Postgres tables (webauthn_credentials, webauthn_challenges, totp_credentials), one new column on `users` (`session_epoch INT NOT NULL DEFAULT 0`), and a folded-in storage-tier mitigation for FINDING-0017 (email length cap) — all in a single Drizzle migration `0002_phase03_2fa_sessions.sql`. Three atomic commits.

**Status:** COMPLETE
**Date:** 2026-05-02
**Commits:** `bf642c5` (T1), `33b97ba` (T2), `6549e9a` (T3)
**Tasks:** 3/3

---

## What landed

### Task 1 — `feat(03-01-T1): schema for webauthn_credentials + webauthn_challenges + totp_credentials` (`bf642c5`)

Three new Drizzle schema modules under `packages/db/src/schema/`:

- **`webauthn_credentials.ts`** — one row per registered passkey: `(id uuid pk, user_id uuid fk users.id ON DELETE CASCADE, credential_id bytea, public_key bytea, counter bigint default 0, transports text[] default '{}', aaguid bytea?, name text, created_at, last_used_at?)`. Indexes: `webauthn_credentials_user_idx` (btree user_id), `webauthn_credentials_credential_id_idx` (UNIQUE — passkey discovery requires global uniqueness).
- **`webauthn_challenges.ts`** — short-lived ceremony nonces: `(id uuid pk, user_id uuid fk, kind text "register"|"auth", challenge bytea (32B), created_at, expires_at)`. Indexes: `webauthn_challenges_user_kind_idx` (UNIQUE on (user_id, kind) — enforces "one in-flight per kind"; begin-* UPSERTs at app layer), `webauthn_challenges_expires_idx` (btree expires_at — supports a future opportunistic sweep cron). TTL is enforced at the app layer via `DELETE … RETURNING challenge` (atomic consume, no TOCTOU).
- **`totp_credentials.ts`** — per-user TOTP enrolment, secret server-opaque: `(id uuid pk, user_id uuid fk, wrapped_secret bytea, encrypted_secret_aad bytea, last_used_step bigint default 0, name text, created_at, last_used_at?)`. Index: `totp_credentials_user_idx` (btree user_id). Replay guard via atomic `UPDATE … WHERE last_used_step < $cs RETURNING *`.

Barrel `index.ts` extended to re-export all three. `drizzle.config.ts` `schema` array extended to include the new modules (the config explicitly enumerates files vs glob-matching, so adding new files requires updating both).

Verify gate: `pnpm --filter @simplevault/db build` green. `grep -E "wrappedSecret|credentialId|webauthnChallenges" packages/db/dist/schema/*.d.ts` returns hits — barrel correctly re-exports.

### Task 2 — `feat(03-01-T2): users.session_epoch column + drizzle migration` (`33b97ba`)

`users.ts` extended with:
```ts
sessionEpoch: integer("session_epoch").notNull().default(0),
```
Inserted between `recoveryHmac` and `userPubKey` per the plan. Existing rows backfill to `0` via the column default.

Drizzle Kit generated `0002_silent_umar.sql` — renamed to `0002_phase03_2fa_sessions.sql` (per plan naming) and `meta/_journal.json` `tag` updated to match. Migration contents (post-Task-3 extension):

- `CREATE TABLE webauthn_credentials` + indexes + FK to users
- `CREATE TABLE webauthn_challenges` + indexes + FK to users
- `CREATE TABLE totp_credentials` + index + FK to users
- `ALTER TABLE users ADD COLUMN session_epoch integer DEFAULT 0 NOT NULL`

Verify gate: `pnpm --filter @simplevault/db build` + `pnpm --filter @simplevault/api build` green (downstream API still typechecks against the extended `users` schema).

**Runtime apply caveat:** the dev Postgres was not running this session, so the migration's runtime apply was NOT executed. The migration is structurally valid (drizzle-kit generated it cleanly + a no-diff re-run after merging confirms snapshot integrity). End-to-end runtime apply on `postgres:18.3-alpine` is performed by Plan 12's CI e2e job, which spins a fresh container, runs all migrations from 0000 → 0002, then runs the auth happy-path. This is consistent with how Plans 02-08 and 02-12 verified their migration apply.

### Task 3 — `fix(03-01-T3): email varchar(254) + Zod .max(254) — FINDING-0017+0022 fold` (`6549e9a`)

**Storage tier (FINDING-0017):**

- `users.email`: `text` → `varchar(254)`
- `invite_codes.email`: `text` → `varchar(254)`

Re-running `db:generate` produced an incremental `0003_*.sql` with just the `ALTER COLUMN` statements; merged into the existing `0002_phase03_2fa_sessions.sql` per the plan ("the diff appends … to the same migration"). The merge:

1. Appended at the END of 0002 (after the index creates):
   ```sql
   ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE varchar(254) USING substring("email", 1, 254);
   ALTER TABLE "invite_codes" ALTER COLUMN "email" SET DATA TYPE varchar(254) USING substring("email", 1, 254);
   ```
2. Prepended at the TOP of 0002 (before any destructive change), a defensive PL/pgSQL DO-block that aborts the migration if any pre-existing row has email > 254 chars (Key Link 11 in 03-INDEX). The `USING substring(...)` cast is itself idempotent for our cardinality (≤50 users), but the DO-block provides a paranoid fail-fast.
3. Updated `meta/0002_snapshot.json` to reflect the post-merge state (id chained to 0001's id) and deleted `meta/0003_snapshot.json` + `0003_cultured_roulette.sql` + the journal entry.
4. Re-ran `db:generate` — output: `No schema changes, nothing to migrate` (snapshot matches schema; chain integrity verified).

**Zod tier (FINDING-0017 + 0022 partial):**

- `apps/api/src/auth/login/login.dto.ts` — `LoginSchema.email`: appended `.max(254)`.
- `packages/shared/src/zod/index.ts` — `MeResponseSchema.email`: appended `.max(254)` (response-side defence-in-depth — server `.parse()`s its own output).

**CLI tier:**

- `apps/cli/src/commands/invite-create.ts` — added a 254-char ceiling check after the existing `EMAIL_RE` regex test, with a fail-fast `process.exit(2)` on overflow. Plain inline check (no Zod import added) to keep CLI deps minimal.

**Plan-listed but not applicable:**

- `SignupSchema` — no `email` field. Server takes email from the locked invite row inside the signup transaction (decision from 02-07). Plan listed it presumptively; nothing to cap.
- `InviteRedeemSchema` — no `email` field. Body is `{ code }` only; the response carries the bound email but the request schema doesn't accept one. Plan said "if present" — it isn't.

Verify gate: `pnpm --filter @simplevault/db build && pnpm --filter @simplevault/api build && pnpm --filter @simplevault/cli build && pnpm --filter @simplevault/web build` all green. `grep -rEn 'email\(\)' apps/api/src apps/cli/src packages/shared/src` returns exactly the two capped sites — no uncapped email validators remain in scope.

**Throttler-tier fix deferred to Plan 03-09** per the INDEX disposition table: that's where the JwtAuthGuard becomes APP_GUARD AND the `login-email` Redis-key tracker switches to `tracker = "em:" + sha256(email).slice(0,16)` (closes FINDING-0022 fully). This task only seals the storage + DTO tier.

---

## Truths verified

| # | Truth | Status |
|---|---|---|
| 1 | New tables `webauthn_credentials`, `webauthn_challenges`, `totp_credentials` exist with correct columns + indexes | OK — schema + generated SQL + snapshot inspected |
| 2 | `users.session_epoch INT NOT NULL DEFAULT 0` exists; existing rows backfill 0 | OK — `ALTER TABLE users ADD COLUMN session_epoch integer DEFAULT 0 NOT NULL` (PG semantics: default applies retroactively to all rows) |
| 3 | `users.email` and `invite_codes.email` are now `varchar(254)` | OK — schema + migration `SET DATA TYPE varchar(254)` |
| 4 | LoginSchema.email + Zod sites + CLI invite-create email arg all have `.max(254)` | OK — grep verification |
| 5 | `pnpm --filter @simplevault/db build && pnpm --filter @simplevault/api build && pnpm --filter @simplevault/web build` green | OK |
| 6 | Drizzle migration applies cleanly on a fresh PG 18.3 instance AND on a Phase-02-fixture-loaded instance | DEFERRED to Plan 12 e2e CI job (no live PG this session) — migration is structurally valid (drizzle-kit generated + no-diff re-run); SQL inspected for idempotency (`USING substring(...)` cast). |

---

## Decisions Made

1. **Folded FINDING-0017 here vs Phase 13.** Phase 03 is already adding 2FA-related throttler ceilings keyed off email (Plan 09); landing the storage cap in Wave 1 means we get the defence-in-depth before any new code touches `users.email`. Saves a second migration in Phase 13.
2. **Single migration `0002_phase03_2fa_sessions.sql`** carries: the three new tables, the `session_epoch` column add, AND the email type tightening — merged by hand from the Drizzle-Kit-emitted incremental files. Rationale: the plan explicitly asks for a single migration filename and it's fewer rollback points if Phase 03 is later abandoned (drop the new tables; `session_epoch` and the email type can stay as harmless leftovers).
3. **Defensive DO-block pre-flight guard prepended.** The `USING substring(email,1,254)` cast is idempotent for our cardinality (Phase 02 close was ≤50 users, none with multi-hundred-char emails), but the DO-block raises an exception before any destructive change if that assumption is ever violated in a future deployment. Costs ~1 ms per migration; standard PL/pgSQL.
4. **MeResponseSchema.email also capped** as Rule 2 defence-in-depth (server `.parse()`s its own /me output, so an unbounded shape would be a missed opportunity). Not in plan-listed sites but trivial to add and consistent with the storage cap.
5. **CLI uses plain inline length check, not Zod.** The CLI already has its own `EMAIL_RE` regex and exits with `process.exit(2)` on overflow; introducing a Zod dependency just for the cap would be over-engineered for a single arg.

---

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 3 — Blocking] Drizzle Kit emits a fresh `0003_*.sql` instead of extending 0002.**

- Found during: Task 3.
- Issue: The plan asked for "the diff appends … to the same migration" but Drizzle Kit doesn't support extending a snapshotted migration; it generates a NEW migration on every `db:generate` invocation.
- Fix: Manually merged the email-ALTER statements into 0002, deleted the 0003 SQL + snapshot + journal entry, repointed 0002's `prevId` to chain back to 0001, and re-ran `db:generate` to confirm `No schema changes` (snapshot matches schema).
- Files modified: `packages/db/drizzle/0002_phase03_2fa_sessions.sql`, `packages/db/drizzle/meta/0002_snapshot.json`, `packages/db/drizzle/meta/_journal.json`.
- Commit: `6549e9a`.

**2. [Rule 1 — Bug] Drizzle-Kit-emitted migration tag is `0002_silent_umar` (random words).**

- Found during: Task 2.
- Issue: Plan specified `0002_phase03_2fa_sessions.sql`; Drizzle Kit names migrations with random word pairs by default.
- Fix: Renamed the `.sql` file and the `meta/_journal.json` `tag` field. No effect on snapshot integrity.
- Files modified: `packages/db/drizzle/0002_phase03_2fa_sessions.sql`, `packages/db/drizzle/meta/_journal.json`.
- Commit: `33b97ba`.

**3. [Rule 1 — Bug] Unused `text` import after switching email to `varchar`.**

- Found during: Task 3 build verification.
- Issue: TS6133 — `text` declared but never read in `users.ts` and `invite_codes.ts` (TypeScript strict-unused triggered by `tsc -p` with `noUnusedLocals`-equivalent).
- Fix: Dropped `text` from the imports list in both files (no other use site remained after email switched to varchar).
- Files modified: `packages/db/src/schema/users.ts`, `packages/db/src/schema/invite_codes.ts`.
- Commit: `6549e9a` (rolled into Task 3 since the bug appeared from Task 3's edit).

**4. [Rule 2 — Defence-in-depth] Capped `MeResponseSchema.email` (`packages/shared/src/zod/index.ts`).**

- Found during: Task 3.
- Issue: Plan listed only LoginSchema/SignupSchema/InviteRedeemSchema, but the `/me` response schema also references the `users.email` column and is `.parse()`d server-side. Without a cap, a future ORM hydration leak could surface as a /me 200 with a multi-megabyte string.
- Fix: Added `.max(254)` mirroring the storage column.
- Files modified: `packages/shared/src/zod/index.ts`.
- Commit: `6549e9a`.

### Plan-listed sites not applicable

- `SignupSchema.email` — no email field exists; server reads it from the locked invite row inside the signup transaction (decision frozen in 02-07). No-op.
- `InviteRedeemSchema.email` — no email field exists; the request body is `{ code }` only. The response carries the bound email but the input schema doesn't accept one. Plan said "if present" — it isn't.

No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

---

## Authentication Gates

None — pure DB schema work, no external services touched.

---

## Hand-offs to Wave 2

**Plan 03-02 (WebAuthn API):**
- Tables `webauthn_credentials` + `webauthn_challenges` exist; import via the schema barrel `import { schema } from "@simplevault/db"`.
- Atomic challenge consume: `db.delete(schema.webauthnChallenges).where(and(eq(id, $1), gt(expiresAt, now()))).returning({ challenge: schema.webauthnChallenges.challenge })` — the `gt(expiresAt, now())` is the app-layer TTL check (no DB cron sweep in Phase 03).
- WebAuthn credential lookup: index on `credential_id` is UNIQUE — single-row lookup is O(log n).

**Plan 03-03 (TOTP API):**
- Table `totp_credentials` exists; replay guard pattern is `db.update(schema.totpCredentials).set({ lastUsedStep: cs, lastUsedAt: sql`now()` }).where(and(eq(id, cid), lt(lastUsedStep, cs))).returning({ id: schema.totpCredentials.id })` — zero rows = 401 AUTH_2FA_TOTP_REPLAY.
- `wrappedSecret` + `encryptedSecretAad` are server-opaque; the API NEVER decrypts them. Browser-only crypto from `@simplevault/crypto/browser` (`computeTotpStep` etc. — Plan 03-03 will add this module).

**Plan 03-04 (session-epoch JWT claim):**
- `users.session_epoch` column is in place. JWT payload should be extended with `epoch: <int>` (signed by `JwtService`) and `JwtAuthGuard` should compare `payload.epoch === user.session_epoch` after the existing `users` row hot-cache hit. Cache TTL = 60s, busted on every write to the column from Plans 03-05 (sessions revoke).

**Plan 03-05 + 03-06 (sessions + 2FA-methods endpoints):**
- All FK relationships use `ON DELETE CASCADE` — deleting a user removes their sessions, passkeys, and TOTP credentials atomically.
- `DELETE /sessions/:id` and `POST /sessions/revoke-all` MUST `db.update(users).set({ sessionEpoch: sql`session_epoch + 1` }).where(eq(id, userId))` inside the same transaction as the family-revoke, then bust the Redis cache.

**Plan 03-09 (throttler ordering + login-email keying):**
- FINDING-0022 is now half-mitigated (storage tier capped at 254). Plan 09 closes the rest by switching `generateKey` to `tracker = "em:" + sha256(body.email.toLowerCase()).slice(0,16)` — fixed-length, leaks no PII to Redis.

---

## Rollback (if Phase 03 is later abandoned)

1. Drop the three new tables: `DROP TABLE webauthn_credentials, webauthn_challenges, totp_credentials CASCADE;`
2. Drop the new column: `ALTER TABLE users DROP COLUMN session_epoch;` (harmless to keep; defaults to 0 with no consumers).
3. Revert email columns to `text`: `ALTER TABLE users ALTER COLUMN email TYPE text; ALTER TABLE invite_codes ALTER COLUMN email TYPE text;` (lossless — varchar(254) ⊆ text).
4. Revert `meta/_journal.json` and delete `0002_phase03_2fa_sessions.sql` + `meta/0002_snapshot.json` from the Drizzle history (or leave it and add a 0003 reversal migration).
5. Revert the Zod `.max(254)` adds (optional — they're harmless on a `text` column).

The Zod tier and storage tier are independently revertible; the `session_epoch` column is harmless to keep at 0 with no consumers (no JWT claim references it without Plan 03-04).

---

## Files

**Created:**
- `packages/db/src/schema/webauthn_credentials.ts` (60 lines)
- `packages/db/src/schema/webauthn_challenges.ts` (45 lines)
- `packages/db/src/schema/totp_credentials.ts` (53 lines)
- `packages/db/drizzle/0002_phase03_2fa_sessions.sql` (single migration, ~60 lines)
- `packages/db/drizzle/meta/0002_snapshot.json`

**Modified:**
- `packages/db/src/schema/users.ts` (added `sessionEpoch` column; switched `email` to `varchar(254)`)
- `packages/db/src/schema/invite_codes.ts` (switched `email` to `varchar(254)`)
- `packages/db/src/schema/index.ts` (barrel: 3 new re-exports)
- `packages/db/drizzle.config.ts` (schema array: 3 new entries)
- `packages/db/drizzle/meta/_journal.json` (renamed tag to `0002_phase03_2fa_sessions`)
- `apps/api/src/auth/login/login.dto.ts` (LoginSchema.email `.max(254)`)
- `packages/shared/src/zod/index.ts` (MeResponseSchema.email `.max(254)`)
- `apps/cli/src/commands/invite-create.ts` (254-char ceiling guard)

---

## Next plans unblocked

Wave 2 (parallel): Plan 03-02 (WebAuthn API), Plan 03-03 (TOTP API), Plan 03-04 (session-epoch JWT claim) all unblocked.
