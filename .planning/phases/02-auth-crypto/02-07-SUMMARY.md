# 02-07 Summary — POST /invite/redeem + atomic POST /auth/signup

**Phase:** 02-auth-crypto
**Plan:** 07
**Wave:** 4
**Date:** 2026-04-29
**Status:** COMPLETE — both endpoints land + e2e-verified end-to-end against PG 18.3.

## Commits

- `4ccfe83` — feat(02-07-T1): invite/redeem endpoint + crypto.service wrapper
- `fee780b` — feat(02-07-T2): auth/signup endpoint with atomic transaction
- `<final>` — docs(02-07): complete signup + invite redeem

## What landed

```
apps/api/src/
├── crypto/
│   ├── crypto.module.ts          # @Global, exports CryptoService
│   └── crypto.service.ts         # HMAC peppers + argon2 params + constant-time eq
├── invite/
│   ├── invite.module.ts
│   ├── invite.controller.ts      # POST /invite/redeem (rate-limited 30/IP/h)
│   ├── invite.service.ts         # informational lookup; never consumes
│   └── invite.dto.ts             # Zod .strict() InviteRedeemSchema
├── auth/
│   ├── auth.module.ts
│   └── signup/
│       ├── signup.controller.ts  # POST /auth/signup (rate-limited 3/IP/h)
│       ├── signup.service.ts     # atomic Drizzle transaction
│       └── signup.dto.ts         # Zod .strict() — every bytea field length-checked
├── common/
│   └── rate-limit.ts             # in-memory FixedWindowRateLimiter (02-09 supersedes)
└── app.module.ts                 # imports CryptoModule, InviteModule, AuthModule
                                  # extends Pino redaction list
packages/shared/src/
└── error-codes.ts                # +AUTH_INVITE_EXPIRED / ALREADY_REDEEMED
                                  # +AUTH_SIGNUP_DUPLICATE_EMAIL
```

Plus a fix to `apps/api/src/common/filters/all-exceptions.filter.ts` so it
honours an embedded `{ error: { code, message } }` body inside an
`HttpException` (without it, every domain error collapsed to the
status-code default and `INVITE_INVALID` was unreachable externally).

## Final request/response contracts (LOAD-BEARING for Plan 02-10 web signup)

### `POST /invite/redeem`

Request:
```json
{ "code": "K3JM-9PXQ-7T4N-22HS-VR8E-A6YF" }
```

Response (200) on hit:
```json
{
  "inviteId": "<uuid>",
  "email": "alice@example.com",
  "argon2Params": { "memoryKiB": 65536, "iterations": 3, "parallelism": 1 },
  "serverArgonSalt": "<base64 16B>"
}
```

Response (400) on every failure (not_found / expired / already_redeemed —
collapsed for anti-enumeration):
```json
{ "error": { "code": "E1006", "message": "Invalid invite", "requestId": "<n>" } }
```

Notes:
- Code regex: `^[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z-]+$`, 8–64 chars.
  Generous superset of the CLI's Crockford base32 + hyphens.
- `serverArgonSalt` comes from env `SERVER_ARGON_SALT` (16 B). The same
  16-B blob is also stored per-user at signup (in `users.server_argon_salt`),
  so future env rotations don't invalidate existing users.

### `POST /auth/signup` (LOAD-BEARING for 02-10 web signup)

Request body — Zod `.strict()`. Every unknown key fails 400 BEFORE any
handler:
```ts
{
  inviteId: string (uuid v4),
  argon2SecretKeyHash: string (base64 -> 32 B exactly),
  argon2Params: { memoryKiB: int >0, iterations: int >0, parallelism: 1 },
  userArgonSalt: string (base64 -> 16 B exactly),
  wrappedMasterDek: string (base64 -> 32..256 B),
  wrappedMasterDekRecovery: string (base64 -> 32..256 B),
  recoveryInnerHash: string (base64 -> 32 B exactly), // sha256(NFKD-normalised phrase)
  userPubKey: string (base64 -> 32 B exactly),         // X25519 pub
  wrappedUserSigningSk: string (base64 -> 32..256 B),
  wrappedUserKxSk: string (base64 -> 32..256 B),
}
```

Response (201) on success — does NOT auto-login (see Issues §auto-login):
```json
{ "userId": "<uuid>", "email": "alice@example.com", "createdAt": "ISO" }
```

Response (400) on invalid invite / expired / already-redeemed / race-lost
/ duplicate-email — all collapse to:
```json
{ "error": { "code": "E1006", "message": "Invalid invite", "requestId": "<n>" } }
```

Response (400) on schema rejection (forbidden field, length mismatch, …):
```json
{ "error": { "code": "E4001", "message": "Invalid request body", "requestId": "<n>" } }
```

Response (429) on burst (3/IP/h):
```json
{ "error": { "code": "E1007", "message": "Too many requests", "requestId": "<n>" } }
```

## Server-storage invariant (REQ-CRYPTO-003) — preserved

The signup DTO is the strict envelope. The `.strict()` Zod schema PROVABLY
rejects every payload carrying:

- `password` / `master_password`
- `secret_key` / `secretKey`
- `recovery_phrase` / `recoveryPhrase` / `mnemonic`
- any unwrapped key

Pino redaction is defence in depth (every signup-body bytea field is in
the redact list, plus the existing `password`/`secretKey`/etc keys). Final
fallback: the `signup.service.ts` catch handler logs only `err_type` +
optional `pg_code`, never the raw error or stack — Drizzle's
`DrizzleQueryError` includes the bytea params in its message, which would
otherwise leak ciphertexts to logs.

## Atomicity proof (e2e against PG 18.3-alpine)

A 10-scenario harness ran end-to-end against a fresh PG. Verified verdicts:

| # | Scenario | Verdict |
|---|----------|---------|
| 1 | invite/redeem happy path -> 200 with envelope | PASS |
| 2 | invite/redeem unknown code -> 400 E1006 | PASS |
| 3 | invite/redeem expired -> 400 E1006 (same shape as 2) | PASS |
| 4 | redeem does NOT consume invite -> redeemed_at still NULL | PASS |
| 5 | signup happy path -> 201, atomic redeem (redeemed_user_id = new user) | PASS |
| 6 | re-attempt signup with same inviteId -> 400 E1006 | PASS |
| 7 | signup with extra `password` field -> 400 E4001 (Zod .strict()) | PASS |
| 8 | concurrent signups same inviteId -> exactly 1 win + 1 E1006 | PASS |
| 9 | dup-email mid-tx -> 400 E1006, invite stays unredeemed (rollback) | PASS |
| 10 | rate-limit reachable (3/IP/h default; env-tunable) | PASS |

Race verdict (key result): Drizzle's `transaction()` with `SELECT … FOR
UPDATE` serialises concurrent signups against the same inviteId. The first
tx commits; the second tx finds `redeemed_at IS NOT NULL` (or the
single-shot UPDATE returns 0 rows) and aborts. This collapses externally
to the same `E1006`.

Rollback verdict: a unique-violation on `users.email` (raised AFTER the
invite-row lock + before the UPDATE) propagates as `DrizzleQueryError`
with pg code `23505` on `.cause`. Caught and translated to `E1006` 400.
The transaction is rolled back by Drizzle automatically — verified by
re-fetching the invite row: `redeemed_at IS NULL`.

## Argon2 / server-storage detail

`argon2Params` returned at `/invite/redeem` come from env (operator-tuned
via `pnpm cli argon2 calibrate`). They're stored per-user in
`users.argon2_params` at signup, with a server-side floor check
(REQ-RATELIMIT-006-style KDF downgrade defence): `memoryKiB ≥ 19456`
AND `iterations ≥ 2` AND `parallelism === 1`. Below-floor params 400
with `VALIDATION_FAILED` (E4001).

The `server_argon_salt` blob also flows env → response → stored. Per-user
storage means env-rotation doesn't invalidate existing verifiers (Plan
02-08 login reads `users.server_argon_salt` from the row, not env).

## Pino redaction — extended

`apps/api/src/app.module.ts` adds (on top of existing
password/secretKey/recovery list):

```
req.body.code                      // raw invite code
req.body.argon2SecretKeyHash
req.body.wrappedMasterDek
req.body.wrappedMasterDekRecovery
req.body.wrappedUserSigningSk
req.body.wrappedUserKxSk
req.body.userPubKey                // even pub key — defence in depth, log-correlation
req.body.recoveryInnerHash
req.body.userArgonSalt
req.body.serverArgonSalt
```

Verified by inspecting `/tmp/sv-api.log` after the e2e harness — no raw
bytea blobs landed in `req.body.*` log fields.

## Audit-event emission (forward-compatible with Phase 10 hash chain)

On signup success:
```json
{ "evt": "signup", "user_id": "<uuid>", "email": "alice@example.com",
  "ts": "2026-04-29T19:47:42.469Z" }
```

Phase 10 will hash-chain these. Phase 02 emits via Pino at `level=log`
(info). Failure paths emit `evt: "auth.signup.fail"` with `reason` enum.

## Env vars consumed

| Var | Purpose | Required |
|---|---|---|
| `SERVER_INVITE_SECRET` | HMAC pepper for `code_hash` lookup | YES |
| `SERVER_RECOVERY_HMAC_SECRET` | outer HMAC for `recovery_hmac` | YES |
| `SERVER_ARGON_SALT` | 16 B blob returned at /invite/redeem + stored per-user | optional in dev (random in-memory + warn); REQUIRED in prod |
| `ARGON2_MEMORY_KIB` / `_ITERATIONS` / `_PARALLELISM` | argon2 params returned to client | optional (defaults 64MiB/3/1) |
| `SIGNUP_RATE_LIMIT` | per-IP signups per window (default 3) | optional — E2E test escape hatch |
| `SIGNUP_RATE_WINDOW_MS` | window size in ms (default 3,600,000) | optional |

## Issues / decisions for downstream plans

### auto-login decision: NO auto-login at signup

The plan's truth list and the caller's carry-overs left this open. Picked
**no auto-login** for Phase 02-07:
- Login (Plan 02-08) is parallel-tracked; sharing session-issue code
  before 02-08 lands would mean duplicating logic.
- Web signup (Plan 02-10) follows up immediately with /auth/login; the
  ergonomic gap is one extra round-trip.
- Phase 02-08 may revisit this if it lands a clean `SessionService` that's
  trivial to inject here.

Plan 02-10 should: after `POST /auth/signup` 201, call `POST /auth/login`
with the same email + the locally-derived `argon2_secret_key_hash` (using
the same `argon2Params` + `server_argon_salt` returned at redeem time).

### Plan 02-08 (login/refresh/logout) hand-offs

- `users.server_argon_salt` is stored per-user — login reads from row, not
  env. Env's `SERVER_ARGON_SALT` is only the seed for *new* users.
- `users.argon2_params` is per-user — login reads from row, runs Argon2id
  with those params, constant-time-compares against
  `users.argon2_secret_key_hash`. (CryptoService exposes `constantTimeEqual`
  already.)
- `CryptoService` is `@Global` — login can `constructor(private crypto:
  CryptoService)` directly.
- The in-memory `FixedWindowRateLimiter` is the placeholder; 02-09 swaps
  in a Redis-backed version. Login should follow the same pattern (one
  limiter per controller).

### Plan 02-09 hand-offs (rate-limit + audit-events)

- Replace `apps/api/src/common/rate-limit.ts` with `@nestjs/throttler` +
  Redis backend. The two consumers are
  `apps/api/src/invite/invite.controller.ts` (30/IP/h) and
  `apps/api/src/auth/signup/signup.controller.ts` (3/IP/h, env-tunable).
- Audit-event emission is currently `this.logger.log({evt:"signup",…})`.
  Phase 10 will pull these into a hash-chained log; the typed shape is
  in Plan 09's audit-events module. Today: just structured Pino fields.

### Deviations from plan + caller carry-overs

1. **Rate-limiting (Rule 1)**: caller offered "nestjs-throttler OR simple
   in-memory counter". Picked in-memory `FixedWindowRateLimiter` to keep
   the new dep surface zero — `@nestjs/throttler` lands as part of 02-09.

2. **Redeem request body shape (Rule 2)**: caller carry-over §2 said
   `POST /invite/redeem` accepts `{ invite_code, email }` with email
   binding. **Plan body** (T1 action) said only `{ code: string }`. Picked
   **plan body** — it's the explicit local spec. The email is server-side
   on the row; client doesn't need to bind it at redeem. Redemption is
   informational anyway. If 02-10 web signup wants to also surface a
   "wrong email" error, that surfaces at login time after signup.
   *Caller carry-over §2 is not violated in spirit:* the email is already
   bound to the code via `invite_codes.email` (lower-cased on insert), and
   the signup body inherits it (the server uses `row.email`, NOT a
   client-supplied email).

3. **Signup body fields (Rule 2)**: caller carry-over §1 listed `email`
   and `server_argon_salt` in the request body. Plan body explicitly
   excludes both — server takes `email` from the locked invite row and
   `server_argon_salt` from env. Picked **plan body**: it's the simpler
   contract and matches the schema (which has no `email` column on the
   request shape). Plan 02-10 web signup uses the (inviteId, artifacts)
   envelope only.

4. **AllExceptionsFilter behavioural change (Rule 1)**: filter now honours
   `{error:{code,message}}` embedded in an HttpException response body.
   Strictly additive: previous status-code-mapped behaviour kicks in only
   when no domain code is present. /health and unrelated endpoints are
   unaffected.

5. **Internal-error sanitisation (Rule 1)**: Drizzle's `DrizzleQueryError`
   message contains the SQL params (bytea ciphertexts). Service catch
   handler logs only `err_type` + `pg_code`, never `err`. Translates
   non-recognised internals to `E5001`/500 (was leaking the stack to the
   AllExceptionsFilter `unhandled exception` log).

No rule-4 deviations, no CHECKPOINT.

## Truths verdict

| # | Truth | Status |
|---|---|---|
| 1 | POST /invite/redeem returns envelope on hit / generic 400 INVITE_INVALID on miss | TRUE |
| 2 | POST /auth/signup creates users row + redeems invite atomically | TRUE — single PG transaction, FOR UPDATE lock, single-shot UPDATE |
| 3 | Signup is rate-limited to 3/IP/hour (REQ-RATELIMIT-003) | TRUE — env-tunable for E2E |
| 4 | Server NEVER receives master_password, secret_key, or recovery_phrase plaintext | TRUE — Zod .strict() enforces, verified by e2e §7 |
| 5 | Idempotency: re-redeem after failed signup until expiry; once redeemed_at set, dead | TRUE — only successful POST /auth/signup sets redeemed_at |
| 6 | argon2_params at redeem from env; stored in users.argon2_params at signup | TRUE — verified by SELECT after e2e |

## Reference artifacts

- `apps/api/src/crypto/crypto.{module,service}.ts`
- `apps/api/src/invite/{invite.module,controller,service,dto}.ts`
- `apps/api/src/auth/auth.module.ts` + `apps/api/src/auth/signup/{controller,service,dto}.ts`
- `apps/api/src/common/rate-limit.ts`
- `apps/api/src/common/filters/all-exceptions.filter.ts` (modified)
- `apps/api/src/app.module.ts` (modified — module imports + Pino redaction)
- `packages/shared/src/error-codes.ts` (extended)
