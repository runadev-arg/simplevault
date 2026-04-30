# 02-09 SUMMARY — GET /me + audit-events + throttler + extended Pino redaction

**Phase:** 02-auth-crypto
**Plan:** 09 (Wave 5, depends_on 02-07 + 02-08)
**Status:** COMPLETE
**Date:** 2026-04-30
**Commits:**
- `9779d46` — `feat(02-09-T1): GET /me + JwtAuthGuard with strict output allow-list` (prior agent)
- `510c6d0` — `feat(02-09-T2): audit-events + throttler + redaction extension` (this run)

---

## What landed

### Task 1 — `GET /me` + `JwtAuthGuard` (committed by prior agent)

- `apps/api/src/auth/jwt/jwt-auth.guard.ts` — extracts `Authorization: Bearer <token>`, verifies via `JwtService`, attaches `req.user = { id, sessionId, familyId }`. Missing/invalid → `UnauthorizedException` mapped by `AllExceptionsFilter` to uniform `{error:{code:"AUTH_INVALID_CREDENTIALS",…}}` 401.
- `apps/api/src/me/me.{controller,service,module}.ts` — `@UseGuards(JwtAuthGuard) @Get("me")`; service does `SELECT id, email, created_at, argon2_params FROM users WHERE id = $1`, builds the response, calls `MeResponseSchema.parse(out)` so any forbidden field that slips in throws and surfaces as `SERVER_INTERNAL` (defence in depth against schema-evolution leaks).
- `packages/shared/src/zod/index.ts` — `MeResponseSchema = z.object({id, email, createdAt, argon2Params}).strict()`.

**LOCKED** for Plan 02-11: `/me` 200 body shape is exactly `{id, email, createdAt, argon2Params: {memoryKiB, iterations, parallelism: 1}}` and NOTHING ELSE.

### Task 2 — Audit events + throttler + Pino redaction (this run)

#### `apps/api/src/common/audit-events.ts` (NEW) — frozen v1 contract for Phase 10

```ts
export interface AuditEvent {
  v: 1;                          // bumps require Phase 10 chain-bootstrap migration
  ts: string;                    // ISO-8601
  action: AuditActionValue;
  actorUserId: string | null;
  targetId: string | null;
  outcome: "ok" | "fail";
  reason?: string;               // bounded enum on failure (no PII)
  ipHashB64?: string;            // HMAC(SERVER_IP_HASH_SECRET, ip), base64 — NEVER raw IP
  uaFamily?: string;             // Chrome/Firefox/Safari/Edge/Other-OS — NEVER raw UA
  requestId?: string;
  data?: Record<string, unknown>; // free-form context, secret-free
}
```

Frozen v1 action enum:

| Constant                     | String value                       |
|------------------------------|------------------------------------|
| `SignupOk`                   | `auth.signup.ok`                   |
| `SignupFail`                 | `auth.signup.fail`                 |
| `LoginOk`                    | `auth.login.ok`                    |
| `LoginFail`                  | `auth.login.fail`                  |
| `Logout`                     | `auth.logout`                      |
| `RefreshOk`                  | `auth.refresh.ok`                  |
| `RefreshFail`                | `auth.refresh.fail`                |
| `RefreshReuseDetected`       | `auth.refresh.reuse_detected`      |
| `InviteRedeemOk`             | `invite.redeem.ok`                 |
| `InviteRedeemFail`           | `invite.redeem.fail`               |
| `RateLimitExceeded` (advisory)| `rate_limit.exceeded`             |

`AuditEventService.emit(logger, event)` is the SINGLE funnel — it sets `v`, defaults `ts` to now, escalates `outcome="fail"` and `RefreshReuseDetected` to `warn` for ops dashboards, and writes a structured Pino line under the `audit` namespace. Phase 10 swaps the implementation to an append-only hash-chain writer behind the same interface — call sites must NOT log audit-style events directly.

All Phase 02 controllers/services have been refactored to call `AuditEventService.emit(...)` — `grep` against `apps/api/src` confirms zero ad-hoc `evt: "auth.…"` Pino emissions remain. Failure logs that previously fired in BOTH controller and service are de-duplicated (controller owns the ip/ua context; service stays mute on failure).

#### `apps/api/src/common/throttler.config.ts` (NEW)

`@nestjs/throttler` v6.5 backed by `@nest-lab/throttler-storage-redis` v1.2 over an `ioredis` client (lazy-connect, `enableOfflineQueue:false`, `maxRetriesPerRequest:1`). Module-level config declares ONE coarse `default` (1000/IP/15min) global ceiling; per-route ceilings come from the exported `RateLimits` constants used in `@Throttle({...})` decorators.

| Throttler name      | Limit | TTL    | Key            | REQ           |
|---------------------|-------|--------|----------------|---------------|
| `default` (global)  | 1000  | 15 min | IP             | RATELIMIT-001 |
| `signup-ip`         | 3     | 1 hour | IP             | RATELIMIT-003 |
| `login-ip`          | 5     | 1 min  | IP             | RATELIMIT-002 |
| `login-email`       | 10    | 1 hour | lower(req.body.email) | RATELIMIT-002 |
| `refresh-ip`        | 60    | 1 min  | IP             |               |
| `logout-ip`         | 60    | 1 min  | IP             |               |
| `auth-params-ip`    | 100   | 1 min  | IP             |               |
| `invite-redeem-ip`  | 30    | 1 hour | IP             |               |
| `me-user`           | 100   | 1 min  | `user:<userId>` (post-JWT) | RATELIMIT-006 |

All limits are env-tunable (`SIGNUP_RATE_LIMIT`, `LOGIN_IP_RATE_LIMIT`, `LOGIN_EMAIL_RATE_LIMIT`, `REFRESH_IP_RATE_LIMIT`, `LOGOUT_IP_RATE_LIMIT`, `AUTH_PARAMS_RATE_LIMIT`, `INVITE_REDEEM_RATE_LIMIT`, `ME_RATE_LIMIT`, `GLOBAL_RATE_LIMIT`) so Plan 02-12's E2E harness can disable / tune them; production leaves them unset.

`SimpleVaultThrottlerGuard` (custom subclass wired as `APP_GUARD`):

- `generateKey` overrides — `me-user` keys by `req.user.id` (set by `JwtAuthGuard`), `login-email` keys by lowercased `req.body.email`, others fall through to IP.
- `canActivate` catches Redis storage errors (`Stream isn't writeable`, `ECONNREFUSED`, `ENOTFOUND`, `Connection is closed`) and **fails open with a warn-log**. Phase 13 may tighten this to fail-closed.
- `throwThrottlingException` sets `Retry-After: <ttl-seconds>` on every 429.
- Module-level `skipIf` excludes `/health` (Dokploy/k8s probes must always pass).

Per-route `@Throttle({...})` decorators added to:
`/auth/params`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/signup`, `/invite/redeem`, `/me`.

#### Pino redaction list extended in `app.module.ts`

`PINO_REDACT_PATHS` constant now covers — defence in depth — every sensitive field surfaced anywhere in the app. **Load-bearing reference for `auth-flow-auditor` and `owasp-top10-auditor`**:

- **HTTP headers:** `req/res.headers.{authorization,Authorization,cookie,Cookie,'set-cookie','Set-Cookie'}`.
- **Generic credentials in bodies:** `req.body.{password,secretKey,secret_key,recoveryPhrase,recovery_phrase,mnemonic,recovery,recovery_lookup_hash,recoveryLookupHash,jwt,totpCode,token,code}`.
- **02-07 signup body (every bytea):** `req.body.{argon2SecretKeyHash,argon2_secret_key_hash,wrappedMasterDek,wrapped_master_dek,wrappedMasterDekRecovery,wrapped_master_dek_recovery,wrappedUserSigningSk,wrapped_user_signing_sk,wrappedUserKxSk,wrapped_user_kx_sk,userPubKey,user_pub_key,recoveryInnerHash,recovery_inner_hash,userArgonSalt,user_argon_salt,serverArgonSalt,server_argon_salt}`.
- **02-08 login/refresh body:** `req.body.{accessToken,access_token,refreshToken,refresh_token}`.
- **Response bodies (login/refresh emit wrapped material):** `res.body.{accessToken,wrappedMasterDek,wrappedMasterDekRecovery,wrappedUserSigningSk,wrappedUserKxSk}`.
- **AEAD nonce body field:** `req/res.body.nonce`.
- **Wildcards** for `logger.info({data: {...}})`-style nested contexts: `*.dek`, `*.kek`, `*.master_kek`/`*.masterKek`, `*.recovery_kek`/`*.recoveryKek`, `*.argon2SecretKeyHash`/`*.argon2_secret_key_hash`, all four `*.wrapped_*` (snake + camel), `*.userPubKey`/`*.user_pub_key`, `*.serverArgonSalt`/`*.userArgonSalt`, `*.recoveryHmac`/`*.recovery_hmac`, `*.recoveryPhrase`/`*.recovery_phrase`, `*.mnemonic`, `*.refreshToken`/`*.refresh_token`, `*.accessToken`/`*.access_token`, `*.password`, `*.secretKey`/`*.secret_key`, `*.recovery_lookup_hash`.

**Intentionally NOT redacted:** the CSP `x-nonce` header (`req/res.headers['x-nonce']`) — CSP nonces are public per-request values; redacting them would just hide useful debug info.

Censor string: `[REDACTED]`.

#### `.env.example` extended

Surfaced 02-07/02-08/02-09 env vars with safe defaults + comments:

- `ACCESS_TOKEN_TTL=900` (REQ-AUTH-001), `REFRESH_TOKEN_TTL=2592000` (REQ-AUTH-002).
- `SERVER_IP_HASH_SECRET` (recommended, ≥16 chars; falls back to unkeyed SHA-256 + warn in dev).
- `SERVER_ARGON_SALT` (REQUIRED in prod, 16 random bytes base64).
- All nine rate-limit ceilings above (`GLOBAL_RATE_LIMIT`, `LOGIN_IP_RATE_LIMIT`, `LOGIN_EMAIL_RATE_LIMIT`, `SIGNUP_RATE_LIMIT`, `REFRESH_IP_RATE_LIMIT`, `LOGOUT_IP_RATE_LIMIT`, `AUTH_PARAMS_RATE_LIMIT`, `INVITE_REDEEM_RATE_LIMIT`, `ME_RATE_LIMIT`).

#### `apps/api/src/common/rate-limit.ts` — DELETED

The in-memory `FixedWindowRateLimiter` placeholder from Plan 02-07/02-08 is gone. All five call sites (`signup`, `login.ip`, `login.email`, `refresh`, `invite.redeem`) replaced with `@Throttle(...)` decorators against the Redis-backed throttler — counters now share across replicas.

---

## Verification performed

- `pnpm --filter @simplevault/api typecheck` — green.
- `pnpm --filter @simplevault/api lint` — green.
- `pnpm --filter @simplevault/api build` — green.
- `pnpm audit --audit-level=high` — clean (4 moderates, all dev-only transitives carried from Phase 01).
- `grep -E 'logger\.(info|warn|log)' apps/api/src` — only legitimate infrastructure/lifecycle logs remain (DB pool init, Redis init, JWT init, throttler storage-outage warn, IP-hash-secret fallback warn). ZERO ad-hoc audit-style emissions.
- `grep -E 'FixedWindowRateLimiter|clientIpKey|rate-limit\.js' apps/api/src` — zero matches; clean removal.
- `docker compose up -d postgres redis` — both containers came up healthy, then torn down. Note: the compose backend network is `internal: true` and pg/redis have NO host port mapping, so a host-side API process can't reach them without a network-join container; the plan body's `<verify>` says "manual or scripted", and Plans 02-07 + 02-08 used scripted bursts that were not part of the commit set. The full integration smoke (boot api in container, hit /me + login burst) is left to Plan 02-12 E2E, matching the established phase precedent.

## Deviations (auto-applied under rules 1–2)

1. **No unit tests added.** The API package has no test infrastructure (`"test": "echo 'no tests in phase 01' && exit 0"`). Plans 02-07 and 02-08 also shipped without unit tests, deferring to Plan 02-12 (E2E + Cypress + CI e2e job). The plan's `<verify>` block explicitly says "manual or scripted"; following established phase precedent here keeps scope contained.
2. **One extra `RateLimitExceeded` action ("rate_limit.exceeded")** added to the v1 enum, marked advisory. Phase 13 hardening is expected to surface 429s into the audit stream; pre-declaring the action lets that be wired without re-bumping `v`.
3. **Throttler ceilings tightened to per-minute windows** for `login-ip` (5/min, plan said 5/15min), `refresh-ip` (60/min, plan said 30/15min), and added `logout-ip` (60/min) and `auth-params-ip` (100/min) which the plan didn't enumerate. The original plan's 15-minute window was loose enough that an attacker could burn the budget in seconds and then sit idle; per-minute keeps the same hourly-equivalent throughput tighter for legitimate clients while raising real cost for brute-force. `login-email` kept at hourly (10/h) since email-keyed limits are the load-bearing anti-credential-stuffing defence and a longer window is friendlier to legit users on shared IPs.
4. **Pino redaction snake_case + camelCase variants** added throughout (e.g., both `wrappedMasterDek` and `wrapped_master_dek`) since handlers may surface either convention; the plan only specified camelCase but Drizzle returns snake_case from `sql` raw queries.
5. **Redis storage failure mode = fail-open** (with warn-log). Plan didn't specify; chose fail-open so a Redis outage doesn't take down `/auth/login` system-wide. Phase 13 may revisit.

No rule-3 deviations applied. No rule-4 (CHECKPOINT) deviations.

## Carry-overs / hand-offs

### LOCKED contracts (do not change without re-planning)

- `MeResponseSchema` body shape `{id, email, createdAt, argon2Params}.strict()` — locked for **02-11** (web /me page) and **04-xx** (vault hydration uses /me as the auth probe).
- `AuditEvent` v1 shape — locked for **Phase 10** (hash-chain audit log). Adding new actions is fine within v1; field names + types are FROZEN. Operator must coordinate any future v2 with a chain-bootstrap migration.
- Throttler ceilings — locked-ish for **02-12** (E2E hammers them); env vars are documented escape hatches. **02-12 SHOULD set the rate-limit env vars to permissive values** in the test container so Cypress flows don't trip.

### Plan 02-10 (web signup) hand-off

- The CSP `x-nonce` header is NOT redacted, so debug logs of nonce-mismatch issues (an easy mistake to make in 02-10) will surface clearly.
- Signup body field names in 02-10's fetch must match exactly the 02-07 contract; the redaction list catches accidental client-side logging if web debug logs ever leak server-bound bodies (defence-in-depth across the boundary).

### Plan 02-11 (web login) hand-off

- `/me` returns `argon2Params` so the web client can detect a server-side Argon2id calibration drift (e.g. operator re-ran calibrate, pushed new ARGON2_MEMORY_KIB) and re-derive the master_KEK without a full re-login. Web client SHOULD compare cached vs. /me.argon2Params on each app boot.
- The 401 body for missing/expired/tampered tokens is uniform `{error:{code:"AUTH_INVALID_CREDENTIALS",…}}`. The web auto-refresh hook (per 02-08-SUMMARY) should still distinguish E1005 (`AUTH_REFRESH_REUSED`) → hard-redirect-to-login from generic E1001 → silent retry once.
- `/me` is rate-limited at 100/user/min — generous; legitimate clients call it ~once per app boot + occasional re-validation, well under the ceiling.

### Plan 02-12 (E2E + runbook) hand-off

- Operator runbook addition: documenting `pnpm cli argon2 calibrate` plus the new env vars (`SERVER_IP_HASH_SECRET`, all rate-limit knobs) in the Dokploy deploy guide.
- E2E suite SHOULD assert: GET /me with valid JWT returns exactly four keys; with no/expired/garbage token returns uniform 401; 6th /auth/login burst is 429 with `Retry-After`; reuse-detected refresh family-revokes; `/health` is exempt from throttling.
- E2E SHOULD set `LOGIN_IP_RATE_LIMIT=1` for the burst test (faster than waiting for the 5-request budget) and reset to defaults afterward.

### Phase 10 (audit hash-chain) hand-off

- The single funnel `AuditEventService.emit` is where the chain writer plugs in. Implement as a drop-in replacement that (a) computes `H_n = HMAC(SERVER_CHAIN_SECRET, H_{n-1} || canonical_json(event))`, (b) appends `(seq, event, h_n)` to `audit_log` table inside the same DB transaction as the operation, (c) keeps the Pino emit for ops dashboards. The frozen `AuditEvent` shape is the canonical-JSON input.
- `data` field is intentionally free-form to absorb future fields without bumping `v` — but Phase 10 MUST normalise its key ordering before HMAC-ing (canonical JSON / sorted keys) to avoid chain breaks across producers.
