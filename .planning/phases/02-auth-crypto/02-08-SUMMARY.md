# 02-08 Summary — POST /auth/login + /auth/refresh + /auth/logout

**Phase:** 02-auth-crypto
**Plan:** 08
**Wave:** 4
**Date:** 2026-04-29
**Status:** COMPLETE — three endpoints land + 21/21 e2e harness PASS against PG 18.3.

## Commits

- `8a370d6` — feat(02-08-T1): /auth/login + /auth/params + JWT + sessions + timing-floor
- `37e9bbe` — feat(02-08-T2): /auth/refresh rotation + reuse-detect + family-revoke
- `34d7252` — feat(02-08-T3): /auth/logout family-revoke + cookie clear

## What landed

```
apps/api/src/
├── common/
│   └── timing-floor.ts                  # DUMMY_HASH + constantTimeEqual32
├── auth/
│   ├── auth.module.ts                   # +Login/Refresh/Logout/Jwt/Session
│   ├── jwt/
│   │   └── jwt.service.ts               # jose HS256 + kid + ACCESS_TOKEN_TTL
│   ├── sessions/
│   │   └── session.service.ts           # createOnLogin / rotate / revokeFamilyByToken
│   ├── login/
│   │   ├── login.controller.ts          # POST /auth/login + GET /auth/params
│   │   ├── login.service.ts             # lookup-then-compare with timing-floor
│   │   └── login.dto.ts                 # Zod .strict()
│   ├── refresh/
│   │   └── refresh.controller.ts        # POST /auth/refresh
│   └── logout/
│       └── logout.controller.ts         # POST /auth/logout
└── app.module.ts                        # extended Pino redaction
apps/api/package.json                    # +jose
```

## Library + version choice — `jose` over `@nestjs/jwt`

Picked **`jose@5.x`** (resolved at install). Rationale:

- Single dep, no `jsonwebtoken` legacy. `jwtVerify` returns a typed
  payload + verified header in one call.
- Explicit `kid` support via `setProtectedHeader({ alg: "HS256", kid: "primary" })`
  — load-bearing for future JWT_SECRET rotation in Phase 03.
- Edge-runtime / Web Crypto compatible — same library can be reused on
  the apps/web side later without churn.

## JWT claim layout

```ts
{
  alg: "HS256",   // protected header
  kid: "primary",
  // ----
  sub: "<user uuid>",
  sid: "<user_sessions row uuid>",
  fam: "<family uuid>",
  iat: <unix>,
  exp: <iat + ACCESS_TOKEN_TTL>,
}
```

`sub`/`sid`/`fam` are all `string` (UUID v4). `kid` lives in the header,
not the payload. ACCESS_TOKEN_TTL defaults to 900 s (15 min); env-tunable.

## Login request/response (LOAD-BEARING for 02-11 web login)

### `GET /auth/params` (public, no auth, no rate-limit)

```json
{ "argon2Params": { "memoryKiB": 65536, "iterations": 3, "parallelism": 1 } }
```

Per the planner's INDEX decision — global params, anti-enumeration. The
client uses these to compute `argon2_secret_key_hash` BEFORE knowing
whether the email exists. The per-user `server_argon_salt` is NOT exposed
here; it's only returned on a successful 200 login (you have to authenticate
to learn the salt).

### `POST /auth/login`

Request — Zod `.strict()`:

```ts
{
  email: string,                    // lowercased + trimmed by Zod
  argon2SecretKeyHash: string,      // base64 -> exactly 32B
}
```

Response 200:

```json
{
  "accessToken": "<jose JWT>",
  "expiresIn": 900,
  "wrappedMasterDek": "<base64>",
  "wrappedMasterDekRecovery": "<base64>",
  "argon2Params": { "memoryKiB": ..., "iterations": ..., "parallelism": 1 },
  "serverArgonSalt": "<base64 16B>",
  "userArgonSalt": "<base64 16B>",
  "userPubKey": "<base64 32B>",
  "wrappedUserSigningSk": "<base64>",
  "wrappedUserKxSk": "<base64>"
}
```

Plus `Set-Cookie: __Host-refresh=<base64url>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000`.

Response 401 (email not found OR verifier mismatch — uniform shape):

```json
{ "error": { "code": "E1001", "message": "Invalid credentials", "requestId": "<n>" } }
```

Response 429 on burst:

```json
{ "error": { "code": "E1007", "message": "Too many requests", "requestId": "<n>" } }
```

## Cookie decision: BOTH (cookie for refresh, body for access)

- `accessToken` is in the JSON body — SPA reads it once, holds in memory,
  sends as `Authorization: Bearer …`.
- `refresh` token is set ONLY in `__Host-refresh` cookie — SPA never sees
  it. /auth/refresh + /auth/logout read it from `req.headers.cookie`.

Attributes (verified end-to-end via curl): `__Host-refresh=…; Path=/;
HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`. The `__Host-`
prefix requires `Path=/` + `Secure` + no `Domain` — all satisfied.

## Timing-floor verdict

The server-side timing concern is the constant-time **memcmp** of the
candidate against the stored verifier (Argon2id is client-side per
REQ-CRYPTO-003 — server never derives anything from the password). On a
user-not-found path we substitute `DUMMY_HASH` (deterministic 32B value
derived from `JWT_SECRET` so attackers can't predict it) so the same
`crypto.timingSafeEqual` call runs unconditionally.

Measured wall-time (5 samples, in-process API + local PG18.3, `LOG_LEVEL=warn`):

| Path                | Avg ms |
|---------------------|--------|
| Happy login         | ~2.3   |
| Wrong verifier      | ~1.1   |
| Unknown email       | ~0.7   |

The delta between the two **failure** paths (the ones an enumeration
attacker probes) is **0.39 ms** — well below any practical signal
threshold over a TLS-NAT-jittered network. The delta between happy and
failure is the cost of the `INSERT user_sessions` row; not a security
concern (an attacker with valid credentials has already won).

The plan called out a +250 ms artificial floor as a **rejected option**.
We do NOT use `setTimeout` (per pitfalls research §8). The DB lookup is
the dominant variable and is bounded by a `lower(email)` UNIQUE index.

## Refresh — rotation flow + reuse detection

In a single Drizzle transaction:

1. `SELECT id, user_id, family_id, used_at, revoked_at, expires_at FROM user_sessions WHERE refresh_token_hash = $1 FOR UPDATE`.
2. Row not found → 401 invalid.
3. `used_at IS NOT NULL` → REUSE DETECTED → `UPDATE user_sessions SET revoked_at = now() WHERE family_id = $f AND revoked_at IS NULL` → emit `auth.refresh.reuse_detected` → 401 `E1005`.
4. `revoked_at IS NOT NULL` OR `expires_at <= now()` → 401 invalid (no family revoke; passive expiry is benign).
5. Otherwise: INSERT new row (same `family_id`, `prev_token_id = old.id`, fresh hash) + UPDATE old row `used_at + revoked_at = now()`. Commit.

## Concurrent rotation race — verdict

Verified via two simultaneous `Promise.all` refresh calls with the same
cookie:

```
statuses=200,401   codes=/E1005
```

The `SELECT ... FOR UPDATE` serialises the two transactions. The first
INSERTs new + UPDATEs old (used_at + revoked_at set). The second blocks
on the row lock; when it's released, the second sees `used_at IS NOT NULL`
on the row it locked → reuse-detect path fires → family-revoke + 401.

This is **fail-closed by design**: a legitimate user whose client somehow
double-fired refresh will be logged out across all devices in that family
and forced to re-login. The trade-off is that this is the only safe
behaviour in the face of "is this a legitimate race or token theft" —
treat it as theft.

## Logout

Reads `__Host-refresh`; on hit `revokeFamilyByToken` revokes every
non-revoked row in the family. Always clears the cookie via `Max-Age=0`.
Idempotent — re-presenting the same cookie returns 200 again.

**Logout-all-sessions** (revoke every family for a user) NOT in scope
for v1 — deferred to Phase 03 (session listing in /me) when it lands
naturally as "revoke this session" + "revoke all".

**Access JWT revocation deferred** — the access token presented by
the now-logged-out client remains valid until its 15-min `exp`. Server-
side revocation requires the session-epoch feature (Phase 03,
REQ-AUTH-004). Documented and accepted.

## E2E harness verdict — 21/21 PASS

Run against fresh `postgres:18.3-alpine` + the migrated schema. All
checks green:

| # | Check | Verdict |
|---|-------|---------|
| 1 | GET /auth/params returns global argon2Params | PASS |
| 2 | login happy 200 + accessToken | PASS |
| 3 | login happy returns wrapped material | PASS |
| 4 | login happy sets __Host-refresh cookie with all attrs | PASS |
| 5 | session row inserted on login | PASS |
| 6 | login wrong verifier 401 + uniform body (E1001) | PASS |
| 7 | login unknown email 401 + uniform body (E1001) | PASS |
| 8 | timing-floor: wrong-vs-unknown delta < 50% baseline | PASS |
| 9 | refresh happy 200 + new accessToken | PASS |
| 10 | refresh rotates cookie | PASS |
| 11 | refresh marks old row used_at + revoked_at | PASS |
| 12 | refresh inserts new row with prev_token_id | PASS |
| 13 | refresh reuse 401 with E1005 | PASS |
| 14 | reuse detection family-revokes the family | PASS |
| 15 | refresh expired 401 | PASS |
| 16 | refresh expired does NOT family-revoke | PASS |
| 17 | logout 200 | PASS |
| 18 | logout clears cookie | PASS |
| 19 | logout family-revokes session | PASS |
| 20 | logout idempotent on repeat | PASS |
| 21 | concurrent refresh race: exactly one 200, one 401 | PASS |

Rate-limit verified separately: `LOGIN_IP_RATE_LIMIT=5` -> 6th attempt
429; `LOGIN_EMAIL_RATE_LIMIT=10` -> 11th attempt 429.

## Pino redaction — extended again

On top of 02-07's signup-body list, 02-08 adds:

```
req.headers['set-cookie']
req.headers['cookie']
res.headers['Set-Cookie']
req.body.accessToken / access_token / refreshToken / refresh_token
res.body.accessToken
res.body.wrappedMasterDek
res.body.wrappedMasterDekRecovery
res.body.wrappedUserSigningSk
res.body.wrappedUserKxSk
```

(`req.headers.authorization` was already in the list from Phase 01.)

## New env vars surfaced (must be added to .env.example before prod cutover)

| Var | Default | Purpose |
|-----|---------|---------|
| `JWT_SECRET` | (required) | HS256 signing key, base64/hex/utf8 ≥32 B. Fail-fast at boot. |
| `ACCESS_TOKEN_TTL` | `900` (s) | Access JWT lifetime. |
| `REFRESH_TOKEN_TTL` | `2592000` (s, 30d) | Refresh cookie + DB row expiry. |
| `SERVER_IP_HASH_SECRET` | (warn fallback) | HMAC key for `ip_hash` in user_sessions. Falls back to unkeyed SHA-256 with a startup warning. Recommended for prod. |
| `LOGIN_IP_RATE_LIMIT` | `5` | Login attempts/IP/15min. |
| `LOGIN_EMAIL_RATE_LIMIT` | `10` | Login attempts/email/15min. |
| `REFRESH_IP_RATE_LIMIT` | `30` | Refresh attempts/IP/15min. |

## Audit-event emission (forward-compatible with Phase 10 hash chain)

Emits structured Pino logs at `level: warn` for failures, `level: info`
for successes:

```
auth.login.ok            { user_id, family_id, ip_hash_b64, ua_family }
auth.login.fail          { reason: "no_user" | "bad_verifier", email_present }
auth.refresh.ok          { user_id, family_id }
auth.refresh.fail        { reason: "no_cookie" | "invalid" }
auth.refresh.reuse_detected { user_id, family_id, ip_hash_b64 }
auth.logout              { user_id, family_id } | { reason: "no_session" }
```

Phase 10 (audit log + hash chain) consumes these directly.

## Hand-offs

### Plan 02-09 (rate-limit + audit-events)

- Replace the 5 `FixedWindowRateLimiter` instances (login.ip, login.email,
  refresh.ip, signup, invite.redeem) with `@nestjs/throttler` backed by
  Redis. Same per-route ceilings + windows.
- Formalise the audit-event Pino shape — currently emitted by string-key
  convention (`auth.login.ok` etc.); 02-09 should ship a typed
  `AuditEvents` enum and a `@AuditEvent()` decorator or thin emit helper.

### Plan 02-11 (web login + auto-refresh)

- Login flow: `GET /auth/params` -> compute Argon2id locally with the
  user-typed master_password + secret_key + the per-user
  user_argon_salt the client kept since signup -> `POST /auth/login`
  with `{ email, argon2SecretKeyHash }`. The 200 response carries
  `serverArgonSalt` + wrapped material; the client now has everything
  needed to derive `master_KEK` and unwrap `master_DEK`.
- Persist `accessToken` in memory only (NEVER localStorage/sessionStorage).
- The `__Host-refresh` cookie is set automatically by the browser; the
  SPA cannot read it. Auto-refresh hook: schedule a `POST /auth/refresh`
  ~60 s before `iat + expiresIn`; on 401 with `E1005` (reuse detected)
  hard-redirect to /login + clear in-memory state.
- Logout: `POST /auth/logout` then drop the in-memory `accessToken` +
  redirect to /login.

### Plan 02-12 (E2E + runbook)

- Cypress flows: signup -> login -> refresh -> logout (happy path);
  reused-token detection (sad); rate-limit-triggers-429.
- Operator runbook entries for the new env vars in the table above
  (especially JWT_SECRET — must be 32 B random, and rotating it
  invalidates every outstanding access token; refresh cookies survive
  because they're DB-stored).

## Deviations (auto rules 1-2 only)

1. **`auth.module.ts` wires Login + Refresh + Logout in T1** — the plan
   prescribes per-task module changes, but Nest dependency injection
   resolves at module-load time and a missing controller would prevent
   T1 from booting at all. Module wire-up landed once in T1.
2. **`/auth/params` is a GET, not POST** — the plan's body text leaves
   the verb unspecified ("public, no auth"). GET semantically matches
   ("read a config blob"). Cacheable.
3. **Single in-process DUMMY_HASH** — plan suggests an HKDF derivation
   from a server-secret. We use sha256 over a versioned label +
   JWT_SECRET, which is functionally equivalent (deterministic +
   secret-keyed) and simpler.
4. **`SERVER_IP_HASH_SECRET` warn-fallback** — analogous to 02-07's
   SERVER_ARGON_SALT pattern: production sets it; dev gets a warn-only
   unkeyed SHA-256. Documented in the env-var table.
5. **`base64url` for the raw refresh-token cookie value** — plan says
   "raw token sent as cookie value"; choosing base64url is the only
   sensible cookie-safe encoding (no padding `=` and no `+`/`/`).

No rule-4 deviations, no CHECKPOINT.

## Hard-won lessons

- The reuse-detection family-revoke must run **inside** the same
  transaction as the `SELECT FOR UPDATE` that saw `used_at IS NOT NULL`.
  If you family-revoke after committing the SELECT, a parallel rotation
  could insert a fresh row in the family between the SELECT and the
  UPDATE — that fresh row would survive the revoke and be a live token
  in a "supposed to be dead" family. Our impl revokes inside the same
  `db.transaction(async tx => { ... })`.

- `__Host-` prefix requires the cookie's `Path=/` AND `Secure` AND no
  `Domain=`. Express's `res.cookie` with `path: "/"`, `secure: true`,
  and no `domain` option satisfies all three. Verified in curl output.

- The plan's truth #1 names the cookie `__Host-refresh` with `Path=/`
  and a 30-day `Max-Age=2592000`. Our default `REFRESH_TOKEN_TTL` is
  `30 * 24 * 60 * 60 = 2_592_000` seconds, matching.
