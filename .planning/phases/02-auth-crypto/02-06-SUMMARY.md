# 02-06 — Operator CLI (`invite create` + `argon2 calibrate`) — SUMMARY

**Status:** DONE — 2026-04-29.
**Commits (atomic, in order):**
- `93f8510` — feat(02-06-T1): apps/cli scaffold + invite create subcommand
- `47c970c` — feat(02-06-T2): argon2 calibrate subcommand
- `<final>`  — docs(02-06): complete Operator CLI

## What landed

New workspace package **`@simplevault/cli`** at `apps/cli`:

```
apps/cli/
├── package.json          # @simplevault/cli, type=module, bin=simplevault-cli
├── tsconfig.json         # NodeNext, target ES2023, types=[node]
├── eslint.config.js
└── src/
    ├── main.ts           # commander entry; nested subcommands
    ├── lib/
    │   ├── base32.ts     # Crockford base32 + hyphenate helper
    │   ├── db.ts         # opens @simplevault/db client; suppresses Drizzle dev logger
    │   └── hmac.ts       # HMAC-SHA256 + SERVER_INVITE_SECRET fail-fast loader
    └── commands/
        ├── invite-create.ts
        └── argon2-calibrate.ts
```

Root `package.json` adds:
```json
"cli":       "pnpm --filter @simplevault/cli exec node dist/main.js",
"cli:build": "pnpm --filter @simplevault/cli build"
```

### Exact CLI invocations

```sh
pnpm cli --help
pnpm cli invite create --email user@example.com [--ttl-days 7 | --expires-in 14d]
pnpm cli argon2 calibrate
```

> Note: the root `cli` script uses `pnpm --filter ... exec node dist/main.js`
> rather than `... start --` so `pnpm cli foo bar` doesn't pass a literal `--`
> as the first argv. Build with `pnpm cli:build` (or `pnpm --filter @simplevault/cli build`)
> before first run.

### Sample stdout (redacted)

`pnpm cli invite create --email user@example.com --ttl-days 7`:
```
2EAK-SYG0-ENNZ-AYYD-DGQ6-BYZ0-1G

(deliver this code to user@example.com out-of-band — it will not be shown again)
expires: 2026-05-06T19:32:38.562Z (in 7 days)
```

`pnpm cli argon2 calibrate` (Apple Silicon dev hardware):
```
Running Argon2id calibration (target ~750ms)…

Measured: 459.3 ms
Params:   memoryKiB=262144 iterations=3 parallelism=1

--- Dokploy env-var snippet (copy/paste) ---
ARGON2_MEMORY_KIB=262144
ARGON2_ITERATIONS=3
ARGON2_PARALLELISM=1
--------------------------------------------

NOTE: calibrator hit the memory cap (262144 KiB). Hardware is faster than the
target; params accept the cap. You may raise the cap in @simplevault/crypto
if you want a longer KDF wall-time.
```

The `262144` (256 MiB) is the `ARGON2_MEMORY_CAP_KIB` ceiling baked into
`@simplevault/crypto`. Production VPS hardware will land below the cap.

## Load-bearing decisions

1. **commander v12.1.0** picked (per plan's "well-maintained, no surprises"
   default). `cac` evaluated and skipped.
2. **Crockford base32** (no I/L/O/U) for invite codes — 16 random bytes
   yield a 26-character base32 string, hyphenated every 4 chars to a
   31-char `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX` form. Storage is the raw
   *string bytes* HMACed (not the underlying entropy bytes) — what the
   operator delivers is what redeem must hash. Plan 02-07's redeem path
   MUST HMAC-SHA256(SERVER_INVITE_SECRET, Buffer.from(submitted_code, "utf8"))
   and constant-time compare against `code_hash`.
3. **`SERVER_INVITE_SECRET`** is a 32+-byte server-side pepper. Decoder
   accepts base64 / hex / utf8; picks the longest decoding ≥ 32 bytes.
4. **`@simplevault/crypto/node` subpath export added** (was missing) so the
   CLI can `import { calibrate, ARGON2_FLOOR_PARAMS, ARGON2_MEMORY_CAP_KIB }
   from "@simplevault/crypto/node"` and pick up types + Node-only barrel
   in lockstep. Non-breaking: the existing `.` and `./types` subpaths are
   untouched.
5. **libsodium-wrappers-sumo@0.7.16 patched** via
   `pnpm.patchedDependencies` (`patches/libsodium-wrappers-sumo@0.7.16.patch`)
   to point its `exports[".".import]` + top-level `module` at the (shipped)
   CJS bundle. Upstream's `.mjs` references a sibling `libsodium-sumo.mjs`
   that isn't shipped, breaking ESM `import` resolution under raw Node.
   The same bug already worked around in `packages/crypto/vitest.config.ts`
   via a vitest alias; the CLI runs through plain Node so it needs the
   patch. Future packages doing `import sodium from "libsodium-wrappers-sumo"`
   from a Node-side runtime will benefit automatically. Patch deletes 2 of
   the original 3 lines and replaces them with the CJS path; trivially
   maintainable.
6. **Drizzle dev-mode query logger suppressed** in the CLI by forcing
   `NODE_ENV=production` if it was unset/`development`. The default Drizzle
   logger writes parameterised query bytes to stdout, which would leak the
   HMAC `code_hash`. We do NOT want to mutate `@simplevault/db` for this
   (its API is fine for the api service); the CLI just opts out at the
   process boundary.

## Env vars added to `.env.example`

| Var | Purpose | Generate |
|---|---|---|
| `SERVER_INVITE_SECRET` | HMAC pepper for invite codes (CLI + signup redeem) | `openssl rand -base64 32` |
| `SERVER_RECOVERY_HMAC_SECRET` | server-side outer HMAC for recovery lookup hashes (consumed first by 02-07) | `openssl rand -base64 32` |
| `ARGON2_MEMORY_KIB` | KDF memory (operator-tunable, default 65536 = 64 MiB) | `pnpm cli argon2 calibrate` |
| `ARGON2_ITERATIONS` | KDF iterations (default 3) | `pnpm cli argon2 calibrate` |
| `ARGON2_PARALLELISM` | KDF parallelism (default 1; libsodium WASM is single-threaded) | `pnpm cli argon2 calibrate` |

The `Phase 02+ will add` comment at the bottom of `.env.example` was pruned
to drop the now-shipped Argon2 vars.

## Verification (per plan)

- `pnpm cli --help` — both subcommands listed (`invite`, `argon2`).
- `pnpm cli argon2 calibrate` — runs end-to-end, prints sane params + measured time.
- **Invite e2e** (per plan):
  1. `docker run -d --name sv-pg-test -p 127.0.0.1:55432:5432 ... postgres:18.3-alpine` — bring up postgres.
  2. `DATABASE_URL=postgres://...:55432/simplevault pnpm exec drizzle-kit migrate` (from `packages/db`) — applied 0000 + 0001 migrations cleanly.
  3. Two invocations of `DATABASE_URL=... SERVER_INVITE_SECRET=$(openssl rand -base64 32) pnpm cli invite create --email …` produced two DIFFERENT codes; both rows landed:
     ```
     email              | hash_hex                                                          | expires_at
     test@example.com   | 9d38ea8a1e1abaa7d5caf91fa041e5d59a1981fc33bceb328b6098d9287f0a61  | 2026-05-06 19:32:38.562+00
     second@example.com | b1c159a13c9c4e1282f44c9f395f45fb7ef5d470c23bbbb006ee197512d011e2  | 2026-05-13 19:32:54.71+00
     ```
     `email` lowercased; `code_hash` populated; raw code never in DB.
  4. Tear-down: `docker rm -f sv-pg-test && docker compose down -v`.
- Fail-fast: `unset SERVER_INVITE_SECRET DATABASE_URL && pnpm cli invite create --email x@y.z` — exits with code 2 + `ERROR: SERVER_INVITE_SECRET is not set.`

## Truths (from plan front-matter)

| # | Truth | Status |
|---|---|---|
| 1 | `pnpm cli invite create --email …` writes a row to invite_codes (code_hash + email + 7-day expiry) and prints a redeemable code on stdout | TRUE |
| 2 | The printed code is single-use (Plan 07 enforces atomically) | TRUE — schema has `redeemed_at` + `redeemed_user_id`; CLI doesn't enforce single-use itself, that's the redeem path's job |
| 3 | Code generation: 16 random bytes → base32-encoded; stored as HMAC(SERVER_INVITE_SECRET, code_bytes) | TRUE (Crockford base32, hyphenated; HMAC over the *string* bytes — see decision 2 above for the redeem-path implication) |
| 4 | `pnpm cli argon2 calibrate` runs Argon2id calibration and prints recommended ARGON2_MEMORY_COST + ARGON2_TIME_COST env values for Dokploy | TRUE — note env var names emitted are `ARGON2_MEMORY_KIB` / `ARGON2_ITERATIONS` / `ARGON2_PARALLELISM` (per .env.example documentation), NOT `ARGON2_MEMORY_COST` / `ARGON2_TIME_COST` (truth's vendor-y wording). The values map 1:1 to the `Argon2Params` shape in `@simplevault/crypto`. |
| 5 | CLI fails fast with a clear error if SERVER_INVITE_SECRET, DATABASE_URL, or any required env is missing | TRUE — exit 2 with stderr message |
| 6 | CLI does NOT log the raw code or the email anywhere except stdout (no pino, no file) | TRUE — Drizzle dev logger suppressed; no pino import; no fs writes |

## Carry-overs into Plan 02-07 (signup)

**Redeem-path contract (LOAD-BEARING):**
- Server reads submitted code from request body, normalises (caller may
  uppercase + strip whitespace and re-hyphenate, but DOES NOT need to —
  the CLI prints the canonical form and operators paste it verbatim).
- Compute `code_hash = HMAC-SHA256(SERVER_INVITE_SECRET, Buffer.from(code, "utf8"))`.
- `SELECT id, email, expires_at, redeemed_at FROM invite_codes WHERE code_hash = $1`
  with constant-time compare on the path that returns the row (PG's `=` on
  bytea is content-equality not constant-time, but the unique index on
  `code_hash` already gives O(1) lookup; if you prefer a true CT compare,
  fetch by id-prefix and Node-side `crypto.timingSafeEqual`).
- Reject if `redeemed_at IS NOT NULL` or `expires_at <= now()`.
- Atomic UPDATE in the same tx as user-row insert: `UPDATE invite_codes SET
  redeemed_at = now(), redeemed_user_id = $new_user WHERE id = $invite_id
  AND redeemed_at IS NULL` — the WHERE clause makes the swap single-shot
  (a second concurrent redeem races and returns 0 rows; treat as 409).

**Email binding:** the CLI lowercases on insert. The signup form's email
must be `email.trim().toLowerCase()` before lookup; the row already has
`email = lower(email)`. Plan 07 should require the submitted email to
match the row's email (the email field is the binding identifier per the
plan's key-links).

**Env vars Phase 02-07 must consume:** `SERVER_INVITE_SECRET` (already in
.env.example), `SERVER_RECOVERY_HMAC_SECRET` (already in .env.example),
the three `ARGON2_*` vars for the API's password-derivation path.

## Deviations

- **Rule 1 (cosmetic / minor scope)**: added `apps/cli/src/lib/base32.ts`
  (plan listed only `db.ts` + `hmac.ts` under `lib/`); pulled the encoder
  out for testability + clarity. No behavioural change.
- **Rule 1**: added `@simplevault/crypto/node` subpath export to enable
  type-correct server-side imports (the existing `.` exports map only
  declared a single `types` entry pointing at the types-only `index.d.ts`).
  Strictly additive, non-breaking.
- **Rule 2**: patched libsodium-wrappers-sumo@0.7.16 via
  `pnpm.patchedDependencies` to fix upstream ESM resolution. Documented
  here + cross-references the existing vitest workaround. Patch lives at
  `patches/libsodium-wrappers-sumo@0.7.16.patch`.
- **Rule 1**: env var names emitted by the calibrator are
  `ARGON2_MEMORY_KIB` / `ARGON2_ITERATIONS` / `ARGON2_PARALLELISM` rather
  than truth #4's `ARGON2_MEMORY_COST` / `ARGON2_TIME_COST` wording — the
  KIB/ITERATIONS/PARALLELISM names match the `Argon2Params` field names in
  `@simplevault/crypto` (which were frozen in Plan 02-02), so the operator's
  Dokploy paste maps 1:1 to what the api code reads.

No rule-4 deviations, no CHECKPOINT.
