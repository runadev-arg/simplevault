---
phase: 03-2fa-sessions
plan: 02
subsystem: auth-2fa-webauthn
tags: [webauthn, simplewebauthn, step-up-jwt, passkeys, 2fa, nestjs]
requires:
  - 03-01 (DB schema: webauthn_credentials, webauthn_challenges, users.session_epoch)
  - 02-08 (Login + JwtService + SessionService primitives)
provides:
  - StepUpJwtService + Require2FAStepUpGuard (consumed by Plans 03-03 TOTP /verify, 03-08 login branch)
  - JwtAuthGuard purpose-claim rejection (defensive — refuses any token with payload.purpose)
  - POST /2fa/webauthn/begin-register + finish-register (auth-required, atomic challenge consume)
  - POST /2fa/webauthn/begin-auth + finish-auth (step-up-required, counter regression check)
  - WEBAUTHN_RP_ID / WEBAUTHN_ORIGIN / WEBAUTHN_RP_NAME / STEP_UP_TOKEN_TTL env vars
  - Audit actions: auth.2fa.webauthn.{register,auth}.{ok,fail}
  - Throttler ceilings: 2fa-register-user, 2fa-webauthn-auth-ip
  - New error codes: AUTH_STEP_UP_REQUIRED (E1011), WEBAUTHN_CHALLENGE_INVALID (E1012), WEBAUTHN_VERIFICATION_FAILED (E1013), AUTH_2FA_NO_METHOD (E1014)
affects:
  - 03-03 (TOTP API — consumes Require2FAStepUpGuard for /2fa/totp/verify)
  - 03-08 (Login branch — consumes StepUpJwtService.sign when user has 2FA enabled)
  - 03-10 (Web settings/security — consumes /2fa/webauthn/* endpoints)
  - 03-12 (E2E — Cypress virtual-authenticator drives all four endpoints)
tech-stack:
  added:
    - "@simplewebauthn/server@^11"
    - "@simplewebauthn/types@^11"
  patterns:
    - "Atomic challenge consume via DELETE … RETURNING (no SELECT-then-DELETE TOCTOU race)"
    - "Step-up JWT discriminator: same secret, different `purpose` claim — JwtAuthGuard rejects any non-undefined `purpose`, Require2FAStepUpGuard ONLY accepts `purpose:'2fa-stepup'`"
    - "WebAuthn ceremony helpers always passed `expectedRPID` + `expectedOrigin` explicitly (defaults are unsafe per @simplewebauthn v11 docs)"
    - "Counter regression rule with `stored>0` exception for never-incrementing authenticators (iCloud Keychain etc.)"
    - "Defensive friend-method (`JwtService.exposeSecret`) for sibling-service secret sharing — keeps secret-rotation surface to a single env var"
key-files:
  created:
    - apps/api/src/twofa/step-up/step-up-jwt.service.ts
    - apps/api/src/twofa/step-up/step-up.guard.ts
    - apps/api/src/twofa/twofa.module.ts
    - apps/api/src/twofa/webauthn/webauthn.dto.ts
    - apps/api/src/twofa/webauthn/webauthn-register.service.ts
    - apps/api/src/twofa/webauthn/webauthn-register.controller.ts
    - apps/api/src/twofa/webauthn/webauthn-auth.service.ts
    - apps/api/src/twofa/webauthn/webauthn-auth.controller.ts
  modified:
    - apps/api/src/auth/jwt/jwt.service.ts (exposeSecret friend method)
    - apps/api/src/auth/jwt/jwt-auth.guard.ts (purpose-claim rejection)
    - apps/api/src/app.module.ts (TwoFaModule registration)
    - apps/api/src/common/audit-events.ts (auth.2fa.webauthn.{register,auth}.{ok,fail})
    - apps/api/src/common/throttler.config.ts (twoFaRegisterUser, twoFaWebauthnAuthIp + user-keying for 2fa-register-user)
    - apps/api/src/auth/login/login.service.ts (Rule 3 stub — `epoch:0` until Plan 04 finalised it; subsequently overwritten by Plan 04's getEpoch hop)
    - apps/api/src/auth/refresh/refresh.controller.ts (same Rule 3 stub; same Plan 04 overwrite)
    - apps/api/package.json (@simplewebauthn/server@^11, @simplewebauthn/types@^11)
    - .env.example (WEBAUTHN_RP_ID, WEBAUTHN_RP_NAME, WEBAUTHN_ORIGIN, STEP_UP_TOKEN_TTL, TWOFA_*_RATE_LIMIT)
    - packages/shared/src/error-codes.ts (E1011..E1014)
duration: ~90min
completed: 2026-05-02
---

# Phase 03 Plan 02: WebAuthn API + step-up JWT Summary

WebAuthn registration + authentication ceremonies behind Phase-02 JWT auth + the new step-up token primitive. Pinned `@simplewebauthn/server@^11`, atomic challenge consume, counter-regression detection, fail-fast boot if `WEBAUTHN_RP_ID` unset in production.

**Status:** COMPLETE
**Date:** 2026-05-02
**Commits:** `5ae823d` (T1), `d90459f` (T2), `3f8dfec` (T3)
**Tasks:** 3/3

---

## What landed

### Task 1 — `feat(03-02-T1): step-up JWT service + Require2FAStepUpGuard + JwtAuthGuard purpose rejection` (`5ae823d`)

- **`StepUpJwtService`** (`apps/api/src/twofa/step-up/step-up-jwt.service.ts`) — sign + verify a step-up JWT carrying `{sub, purpose:"2fa-stepup", epoch}`. TTL default 120s, env `STEP_UP_TOKEN_TTL`. Same `JWT_SECRET` as the access token (single secret-rotation surface) — safety enforced by the `purpose` discriminator. Verifier asserts `payload.purpose === "2fa-stepup"` AND `typeof epoch === "number"`; anything else throws.
- **`Require2FAStepUpGuard`** (`apps/api/src/twofa/step-up/step-up.guard.ts`) — `Authorization: Bearer <stepUp>` Express guard. On verify success attaches `req.stepUp = {sub, epoch}`; on failure throws uniform 401 `AUTH_STEP_UP_REQUIRED`.
- **`JwtAuthGuard` extension** — added a `decodeJwt` pre-check. If the unverified payload contains a `purpose` claim, refuse 401 immediately (without reaching `verifyAccessToken`). This makes step-up tokens hard-rejected on `/me`, `/sessions/*`, etc. — the dual of the step-up guard.
- New error code: `AUTH_STEP_UP_REQUIRED = "E1011"` (plus reservations for the rest of the WebAuthn flow: `WEBAUTHN_CHALLENGE_INVALID = "E1012"`, `WEBAUTHN_VERIFICATION_FAILED = "E1013"`, `AUTH_2FA_NO_METHOD = "E1014"`).
- `.env.example` documents `STEP_UP_TOKEN_TTL=120`.
- Friend method `JwtService.exposeSecret(): Uint8Array` so `StepUpJwtService` can share the symmetric secret. Documented as package-private.

Verify gate: `pnpm --filter @simplevault/api build` green. Step-up tokens cannot impersonate access tokens (purpose-claim rejection in `JwtAuthGuard`).

### Task 2 — `feat(03-02-T2): /2fa/webauthn/{begin,finish}-register + @simplewebauthn dep` (`d90459f`)

- **Dependency**: `@simplewebauthn/server@^11` and `@simplewebauthn/types@^11` pinned in `apps/api/package.json`. The `types` package is required because v11's `RegistrationResponseJSON` / `PublicKeyCredentialCreationOptionsJSON` are NOT re-exported from `server` — they live in the dedicated `types` module. Slight deviation from the plan (which said only `server` is needed) — see Deviations §1.
- **`WebauthnRegisterService`** (`webauthn-register.service.ts`):
  - `onModuleInit` reads `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN`. **Fail-fast in production** if RP_ID or ORIGIN unset. Dev fallbacks: `rpId="localhost"`, `origin="http://localhost:3000"`.
  - `beginRegister` calls `generateRegistrationOptions` with `attestationType="none"`, `authenticatorSelection.userVerification="required"`, `authenticatorSelection.residentKey="preferred"`, `supportedAlgorithmIDs=[-7, -257]` (ES256 + RS256), and `excludeCredentials` populated from existing `webauthn_credentials` rows for the user. Then UPSERTs into `webauthn_challenges (kind='register')` so the unique `(user_id, kind)` index enforces "one in-flight register per user".
  - `finishRegister` performs **atomic challenge consume**: `DELETE FROM webauthn_challenges WHERE user_id = $1 AND kind = 'register' RETURNING challenge, expires_at`. Zero rows OR `expires_at <= now()` → 400 `WEBAUTHN_CHALLENGE_INVALID` + audit fail. Then `verifyRegistrationResponse({response, expectedChallenge, expectedOrigin, expectedRPID, requireUserVerification: true})` — origin/RPID **passed explicitly per Key Link 9**. On verify success, INSERT into `webauthn_credentials` with v11's `registrationInfo.credential.{id,publicKey,counter,transports?}` shape + `aaguid` (informational). Emits `auth.2fa.webauthn.register.ok`.
- **`WebauthnRegisterController`** — `POST /2fa/webauthn/begin-register` and `POST /2fa/webauthn/finish-register`, both `@UseGuards(JwtAuthGuard)` and throttled by `2fa-register-user` (10/min user-keyed by default).
- **`TwoFaModule`** wired into `AppModule`. Imports `AuthModule` (for `JwtService`) and `DbModule`. Plan 03's executor picked up my module file and added their `TotpController` / `TotpService` to the same `@Module` decorator (concurrent edit; module file ended up co-owned).
- **Audit enum** extended: `auth.2fa.webauthn.{register,auth}.{ok,fail}`.
- **Throttler config** extended: `RateLimits.twoFaRegisterUser` (user-keyed via the `generateKey` override) and `RateLimits.twoFaWebauthnAuthIp` (IP-keyed). The `2fa-register-user` keying makes a per-user ceiling that survives multi-IP attacks.
- `.env.example` documents `WEBAUTHN_RP_ID=pass.runadev.com`, `WEBAUTHN_RP_NAME=SimpleVault`, `WEBAUTHN_ORIGIN=https://pass.runadev.com`, `TWOFA_REGISTER_RATE_LIMIT=10`, `TWOFA_WEBAUTHN_AUTH_RATE_LIMIT=30`.

Verify gate: `pnpm --filter @simplevault/api build` green.

### Task 3 — `feat(03-02-T3): /2fa/webauthn/{begin,finish}-auth + counter regression` (`3f8dfec`)

- **`WebauthnAuthService`** (`webauthn-auth.service.ts`):
  - `beginAuth(userId)` returns `generateAuthenticationOptions` with `allowCredentials` from the user's `webauthn_credentials`. Empty creds → 400 `AUTH_2FA_NO_METHOD`. UPSERTs a `webauthn_challenges (kind='auth')` row, TTL 120s.
  - `finishAuth(userId, body, ip, ua)` — atomic challenge consume (DELETE … RETURNING), credential lookup by `(user_id, credential_id)` (the credential_id is base64url-decoded from `body.id`), then `verifyAuthenticationResponse` with `expectedRPID + expectedOrigin` passed explicitly + `requireUserVerification: true`. On verify success applies the **counter regression rule** (Truth 4 + Key Link 4): `if (stored.counter > 0 && newCounter <= stored.counter) → 401 + audit auth.2fa.webauthn.auth.fail reason="counter_regression"`. The `stored>0` guard preserves the never-incrementing-authenticator path (iCloud Keychain etc. — see @simplewebauthn docs). Updates `counter` + `last_used_at`, then mints a fresh session via `SessionService.createOnLogin` + `JwtService.signAccessToken` with `epoch = sessions.getEpoch(userId)` (Plan 04's helper) and a defensive fallback that reads `users.session_epoch` directly if `getEpoch` isn't yet shipped (handles concurrent-execution hand-off).
  - Returns the same body envelope shape as Phase-02 1FA-only `/auth/login` 200 — `{accessToken, expiresIn, wrappedMasterDek, wrappedMasterDekRecovery, argon2Params, serverArgonSalt, userArgonSalt, userPubKey, wrappedUserSigningSk, wrappedUserKxSk}` — so the web client's existing post-login machinery works unchanged.
- **`WebauthnAuthController`** — `POST /2fa/webauthn/begin-auth` and `/finish-auth`, both under `@UseGuards(Require2FAStepUpGuard)`. Throttled by `2fa-webauthn-auth-ip` (30/min). `finishAuth` sets the `__Host-refresh` cookie identical to a Phase-02 login.
- Audit fail reasons enumerated: `challenge_invalid`, `challenge_expired`, `bad_credential_id`, `credential_not_found`, `verification_threw`, `verification_failed`, `counter_regression`. All bounded enum values — no PII.

Verify gate: `pnpm --filter @simplevault/api build` green.

---

## Truths verified (1–4 + step-up partition)

| # | Truth | Status |
|---|-------|--------|
| 1 | `POST /2fa/webauthn/begin-register` (auth required) returns 32-byte challenge, `rp.id=WEBAUTHN_RP_ID`, `rp.name="SimpleVault"`, `pubKeyCredParams=[-7,-257]`, `userVerification="required"`, `attestation="none"`, plus a `webauthn_challenges` row with TTL=120s | OK — code-inspected; replay returns 400 `WEBAUTHN_CHALLENGE_INVALID` after consume |
| 2 | `POST /2fa/webauthn/finish-register` consumes the challenge atomically (DELETE … RETURNING), verifies via @simplewebauthn v11 with `expectedRPID` + `expectedOrigin` explicit, INSERTs `webauthn_credentials`, returns `{id, name}` | OK — `register.service.ts` lines 168–172 (atomic DELETE … RETURNING) + 184–197 (origin/RPID explicit) |
| 3 | `POST /2fa/webauthn/begin-auth` requires step-up token (`AUTH_STEP_UP_REQUIRED` if missing/invalid), returns `allowCredentials` from `webauthn_credentials`, fresh `webauthn_challenges (kind='auth')` row TTL=120s | OK — `Require2FAStepUpGuard` on the controller; service-level UPSERT |
| 4 | `POST /2fa/webauthn/finish-auth` verifies assertion, asserts counter regression rule (`stored>0 && new<=stored` → reject + audit), bumps counter, consumes challenge atomically, mints full session | OK — `auth.service.ts` lines 217–225 (counter check) + 211–215 (verify) + 147–161 (atomic consume) |
| 5 (partial) | Step-up JWT separation: `purpose:"2fa-stepup"`, NO `sid`/`fam`, exp = iat + STEP_UP_TOKEN_TTL; `JwtAuthGuard` rejects any token with `purpose !== undefined`; `Require2FAStepUpGuard` only accepts `purpose:"2fa-stepup"` | OK for the JWT primitives. Plan 04 finalised the `epoch` claim in the access token; Plan 08 will wire `/auth/login` to mint the step-up token when 2FA is enrolled. |

WebAuthn ceremonies satisfy **Key Links 1, 2, 5, 9** explicitly (RP ID env-bound + fail-fast in prod; atomic challenge consume; step-up token bounded to /2fa/* via `purpose` discriminator on both guards; `expectedRPID` + `expectedOrigin` passed explicitly to `verifyRegistrationResponse` AND `verifyAuthenticationResponse`).

Sanity grep for plaintext-secret semantics in this plan's files — `master_DEK` / `master_kek` only appear in `webauthn-auth.service.ts` and `webauthn-auth.controller.ts` as references to the WRAPPED ciphertext blobs returned in the login envelope (mirroring `/auth/login`'s existing behaviour). No plaintext-secret reads/writes; the `wrappedMasterDek` field is the ciphertext blob the browser unwraps client-side. PASS.

---

## @simplewebauthn version + v11 API change notes (per plan output requirement)

**Version chosen:** `^11.0.0` (resolved 11.0.0 at install time). Pinned per Key Link 9 because v10 → v11 introduced a breaking shape change in `verifyRegistrationResponse`'s return value:

- **v10 (deprecated)**: `verification.registrationInfo.{credentialID, credentialPublicKey, counter, transports?, aaguid?}` (flat shape).
- **v11 (current)**: `verification.registrationInfo.credential.{id, publicKey, counter, transports?}` + sibling `verification.registrationInfo.aaguid`.

This plan code targets v11's nested shape exclusively. If the operator's pin slips to v10, registration verification will throw at runtime when reading `ri.credential.id`. The `registrationInfo.aaguid` field is also v11-positioned (a hex-string at the top level of `registrationInfo`, not a Buffer at `credential.aaguid`). The `pnpm-lock.yaml` should be the source of truth.

**Why types come from `@simplewebauthn/types`**: v11's `server` package re-exports the *function-input/output* types (`GenerateRegistrationOptionsOpts` etc.) but NOT the JSON envelope types (`RegistrationResponseJSON`, `PublicKeyCredentialCreationOptionsJSON`, `AuthenticatorTransportFuture`, …). Those live in the sibling `@simplewebauthn/types` package. Adding `@simplewebauthn/types@^11` as a direct dep is the cleanest way to consume them; alternative was a deep import path which @simplewebauthn explicitly discourages.

**Atomic DELETE…RETURNING rationale**: a SELECT-then-DELETE sequence opens a TOCTOU window between (a) reading the challenge for verification and (b) deleting it for replay-prevention. Two concurrent finish-register requests for the same user could each pass step (a) before either reaches step (b), so the second one would re-verify against an already-consumed challenge. Postgres `DELETE … RETURNING` is a single statement under one MVCC snapshot — exactly one of the racers sees the row, the other gets zero rows.

**Counter regression rule**: `if (stored.counter > 0 && newCounter <= stored.counter) → reject`. The `stored > 0` guard exists because some authenticators (notably resident-key passkeys synced via iCloud Keychain) **never increment the counter** — they always send 0. Rejecting `newCounter <= 0` would lock out every Apple-authenticator user on their first authentication. The plan's exact rule.

**Env vars + boot fail-fast**: `WEBAUTHN_RP_ID` and `WEBAUTHN_ORIGIN` MUST be set when `NODE_ENV=production`; `WebauthnRegisterService.onModuleInit` throws and refuses to boot otherwise. The runbook update lives in Plan 12.

---

## Decisions Made

1. **Single-secret JWT vs split-secret step-up.** Step-up token signed with the same `JWT_SECRET` as the access token, discriminated by `purpose:"2fa-stepup"`. Rationale: a split-secret design halves the attacker's effective key-rotation surface (compromise of either secret is total) while doubling operator ceremony. The discriminator approach gives the same security at lower op cost — provided BOTH guards are paranoid about their respective `purpose` claims (verified: `JwtAuthGuard` rejects any non-undefined `purpose`; `Require2FAStepUpGuard` only accepts `purpose:"2fa-stepup"`).
2. **`JwtService.exposeSecret()` friend method.** Alternative: extract the secret-loading logic into a `JwtSecretProvider` Nest provider both services depend on. The friend method is 1 line of code + 1 paragraph of comment vs ~30 lines for the split. Re-evaluate in Phase 13 if a third token kind appears.
3. **Atomic challenge consume via raw SQL (`db.execute(sql\`DELETE … RETURNING\`)`)** rather than Drizzle's `db.delete().returning()` builder. The builder works, but `RETURNING` semantics on bytea + timestamp columns occasionally surface library-level edge cases; the raw SQL is unambiguous and the audit trail is easy to grep.
4. **Defensive `readEpoch` fallback in `WebauthnAuthService.finishAuth`.** If `SessionService.getEpoch` (Plan 04's helper) isn't yet shipped at the moment my code first runs, fall back to a direct `SELECT session_epoch FROM users WHERE id = ?` query. Kept the fallback in place even after Plan 04 shipped because parallel-execution may surface order-of-arrival issues; it's a 4-line safety net.
5. **Body envelope shape for `/finish-auth`** mirrors Phase-02 `/auth/login` 200 response exactly. Rationale: the web client's post-login key-store hydration (Plan 02-11) already handles this shape; reusing it means the 2FA path is "just another login" from the client's perspective. Alternative considered: emit only `{accessToken, expiresIn}` and have the client refetch wrapped material via a hypothetical `/me/wrapped`. Rejected — adds a round-trip; the wrapped material is already cached server-side anyway.

---

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 3 — Blocking] Plan 04's `epoch` claim made the build red.**

- **Found during:** Task 1 build verification (after committing).
- **Issue:** Plan 04's parallel commit `aae6636` made `epoch: number` a required field on `AccessTokenClaims`. Existing call sites in `apps/api/src/auth/login/login.service.ts:87` and `apps/api/src/auth/refresh/refresh.controller.ts:74` (NOT in my files-modified list — owned by Phase 02 + Plan 04) instantly broke type-checking with TS2345. Build was red across plans.
- **Fix:** Added `epoch: 0` stub at both call sites with a comment documenting the Plan-04 hand-off. Per the plan's own "Note for Plan 04 hand-off": `"The epoch:0 stub above will be replaced by await this.sessions.getEpoch(userId) (Redis-cached read of users.session_epoch). Plan 04 makes this surgical replacement in 3 lines."` — I literally introduced the stub the plan anticipated. Plan 04 subsequently committed `b3bc306` ("wire epoch into login + refresh signing sites"), replacing my stub with their getEpoch hop.
- **Files modified:** `apps/api/src/auth/login/login.service.ts`, `apps/api/src/auth/refresh/refresh.controller.ts`.
- **Commit:** rolled into Task 2 (`d90459f`).

**2. [Rule 3 — Blocking] Plan 03's `totp.service.ts` had an unused-`logger` lint error.**

- **Found during:** Task 2 build verification.
- **Issue:** Plan 03 (parallel) had an in-flight `apps/api/src/twofa/totp/totp.service.ts` with `private readonly logger = new Logger(TotpService.name);` and no use site yet. TypeScript `noUnusedLocals` rejected the build. I do not own that file, but my build needed to be green to verify my own work.
- **Fix:** Added `void this.logger;` in the constructor with a comment ("Phase 03-02 cross-plan unblock fix"). Single line; Plan 03 wired the audit-emission paths in their subsequent commit and the `void` line became harmless.
- **Files modified:** `apps/api/src/twofa/totp/totp.service.ts`.
- **Commit:** rolled into Task 2 (`d90459f`).
- **Note:** I considered raising this as a checkpoint:decision but the plan explicitly says "If you discover a shared file that must change for your plan to work, treat it as Rule 3 (blocking) — fix minimally and document it as a deviation; do not refactor". Single-line minimal fix executed accordingly.

**3. [Rule 3 — Blocking] @simplewebauthn JSON-envelope types live in a sibling package.**

- **Found during:** Task 2 build verification.
- **Issue:** The plan's pseudocode imports `RegistrationResponseJSON` / `PublicKeyCredentialCreationOptionsJSON` from `@simplewebauthn/server`. v11 doesn't re-export those — they're in `@simplewebauthn/types`. Build failure: `Module '"@simplewebauthn/server"' has no exported member 'RegistrationResponseJSON'`.
- **Fix:** `pnpm --filter @simplevault/api add @simplewebauthn/types@^11` and changed the type imports to `@simplewebauthn/types`. No semantic change.
- **Files modified:** `apps/api/package.json`, `pnpm-lock.yaml`, `apps/api/src/twofa/webauthn/webauthn-register.service.ts`, `webauthn-register.controller.ts`, `webauthn-auth.service.ts`, `webauthn-auth.controller.ts`.
- **Commit:** rolled into Task 2 (register sites) + Task 3 (auth sites).

**4. [Rule 1 — Bug] Initial `excludeCredentials` shape mismatch (`exactOptionalPropertyTypes`).**

- **Found during:** Task 2 build verification.
- **Issue:** TypeScript with `exactOptionalPropertyTypes` rejected `transports: undefined` on objects whose declared type was `{transports?: AuthenticatorTransportFuture[]}`. `?:` in strict mode means "absent OR T", not "absent OR T OR undefined".
- **Fix:** Construct the object conditionally — only set `transports` when `Array.isArray(t) && t.length > 0`.
- **Files modified:** `webauthn-register.service.ts`, `webauthn-auth.service.ts`.
- **Commit:** rolled into Task 2 + Task 3.

### Concurrent-edit collisions documented

**a. `apps/api/src/twofa/twofa.module.ts` co-ownership.**
My Task 2 commit created the module with `WebauthnRegisterController/Service` only. Plan 03's executor concurrently extended it with `TotpController/Service` (their commit `ca13403` includes the module file change). My Task 3 added `WebauthnAuthController/Service` to the same module file; Plan 03 then absorbed those imports into their commit alongside their TOTP additions, so the imports for my Task 3 controller + service ended up landing in `ca13403` (Plan 03's commit) rather than `3f8dfec` (my T3). The controller + service files themselves are in my T3 commit; only the module-wiring lines crossed over.

**b. `apps/api/src/common/audit-events.ts` and `throttler.config.ts`.**
Plan 03 concurrently added their TOTP audit actions and TOTP-verify throttler. The two sets of additions don't conflict; both landed cleanly in their respective commits.

**c. Initial T1 commit chaos.**
The first attempts at the T1 commit (`b199299`, `645c00f`) accidentally bundled Plan 03's then-staged-but-uncommitted `packages/crypto/src/totp.ts` + `totp.test.ts` files because `git add <list>` interleaved with another agent's staging activity. Plan 04 then `git commit --amend`-ed to add their RED test on top of `645c00f`, producing `4adcc67`, which a subsequent cherry-pick re-tagged as `5ae823d`. The end state is correct (my T1 work is at `5ae823d`; Plan 03's totp files were absorbed into the same commit but their content is intact and they were committed-anyway-by-Plan-03 in a later commit), just messy in the log. No code was lost; the SUMMARY records this for auditability.

### Plan-listed sites adjusted

- The plan code has `excludeCredentials: existing.map(c => ({ id: c.credentialId, type: "public-key", transports: c.transports }))` with raw `Buffer` values. v11's typed signature requires `id: Base64URLString` (i.e. base64url-encoded string). Adapted to `id: Buffer.from(c.credentialId).toString("base64url")`. Functionally identical; type-correct.
- Plan suggested adding the Zod webauthn DTO schemas under `packages/shared/src/zod/index.ts`. Kept them in `apps/api/src/twofa/webauthn/webauthn.dto.ts` instead because (a) the WebAuthn JSON shape is library-private + version-pinned + already 30+ lines, so duplicating across packages adds noise, and (b) the web client (Plan 10) doesn't need to validate request bodies it just constructed from `navigator.credentials.create()` — server-side Zod-validation is sufficient. Phase 10 may surface a counter-decision; revisit then.

### Not applicable

- Plan listed `apps/api/src/twofa/webauthn/webauthn.dto.ts` as a single file; I kept it in one file per the plan and added Zod schemas for both register-finish and auth-finish bodies. The shape of the DTO is intentionally minimal — top-level fields with `passthrough()` for the deeply-nested authenticator-response sub-objects, since `verifyRegistrationResponse` / `verifyAuthenticationResponse` do the deep crypto-aware validation.

No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

---

## Authentication Gates

None — all work was code-only; no external CLI authentication required. `pnpm add @simplewebauthn/server@^11` and `@simplewebauthn/types@^11` worked offline against the local registry mirror.

---

## Hand-offs to downstream waves

**Plan 03-03 (TOTP API) — already consumed:**
- `Require2FAStepUpGuard` is exported from `TwoFaModule`. TOTP `/verify` route should `@UseGuards(Require2FAStepUpGuard)` and read `req.stepUp.sub` for the userId. Confirmed Plan 03's `totp.controller.ts` does this.
- `StepUpJwtService` is exported for Plan 08's login branch.

**Plan 03-04 (session-epoch JWT claim) — already consumed:**
- The `epoch:0` stub in login + refresh has been replaced by Plan 04's `await this.sessions.getEpoch(userId)` hop. My code in `webauthn-auth.service.ts:finishAuth` has a defensive fallback (`readEpoch`) that prefers `SessionService.getEpoch` if available and falls back to a direct query — both paths work; Plan 04's helper is preferred.

**Plan 03-08 (login branches on 2FA presence):**
- When the verified user has ≥1 row in `webauthn_credentials` OR `totp_credentials`, `/auth/login` should NOT mint a full session. Instead: `await stepUpSvc.sign(user.id, currentEpoch)` + return `{stepUpToken, twoFa:{webauthnAvailable, totpAvailable}}` with HTTP 200. The `StepUpJwtService` API is `sign(userId, epoch) → string`; TTL is enforced internally.

**Plan 03-09 (throttler ordering fix):**
- The new ceilings `2fa-register-user` (user-keyed via `generateKey` override), `2fa-webauthn-auth-ip` (IP-keyed default), `2fa-verify-ip` (Plan 03's TOTP IP-keyed) are in place. Plan 09's APP_GUARD-JwtAuthGuard refactor must add `/2fa/webauthn/begin-auth` and `/2fa/webauthn/finish-auth` to the `@Public()`-equivalent allow-list — these routes use `Require2FAStepUpGuard`, not `JwtAuthGuard`. (Plan 09's INDEX entry already enumerates them.)

**Plan 03-10 (web settings/security) and 03-12 (E2E):**
- Endpoints conform to the truths' shapes. `begin-register` returns the v11 `PublicKeyCredentialCreationOptionsJSON` object verbatim; `finish-register` body is `{response: RegistrationResponseJSON, name: string}`; `finish-auth` body is `{response: AuthenticationResponseJSON}`.

---

## Rollback (if Plan 03-02 is reverted standalone)

1. Revert commits `5ae823d`, `d90459f`, `3f8dfec` in reverse order.
2. Drop the `@simplewebauthn/{server,types}` deps from `apps/api/package.json` + re-lock.
3. Remove the `TwoFaModule` registration from `app.module.ts`. Plans 03-03 and 03-04 will partially break — they share the module. So a Plan-02-only rollback is NOT a clean slice; the realistic rollback is "revert Phase 03 entirely", which the Phase-03 INDEX already prescribes via dropping the new tables and removing the `session_epoch` column.
4. The `epoch` claim is co-owned by Plan 04; reverting only Plan 02 would leave Plan 04's epoch logic standing, which is fine (it's structurally independent).

The `JwtAuthGuard` purpose-claim rejection is harmless if no token ever carries `purpose` — i.e. it's reverse-compatible.

---

## Files

**Created (this plan):**
- `apps/api/src/twofa/step-up/step-up-jwt.service.ts` (96 lines)
- `apps/api/src/twofa/step-up/step-up.guard.ts` (84 lines)
- `apps/api/src/twofa/twofa.module.ts` (~50 lines, co-owned with Plan 03)
- `apps/api/src/twofa/webauthn/webauthn.dto.ts` (~70 lines)
- `apps/api/src/twofa/webauthn/webauthn-register.service.ts` (~225 lines)
- `apps/api/src/twofa/webauthn/webauthn-register.controller.ts` (~85 lines)
- `apps/api/src/twofa/webauthn/webauthn-auth.service.ts` (~280 lines)
- `apps/api/src/twofa/webauthn/webauthn-auth.controller.ts` (~110 lines)

**Modified:**
- `apps/api/src/auth/jwt/jwt.service.ts` (+`exposeSecret()`; `epoch` claim already added by Plan 04)
- `apps/api/src/auth/jwt/jwt-auth.guard.ts` (`decodeJwt` purpose pre-check)
- `apps/api/src/app.module.ts` (TwoFaModule registration)
- `apps/api/src/common/audit-events.ts` (4 new actions, all `auth.2fa.webauthn.*`)
- `apps/api/src/common/throttler.config.ts` (2 new ceilings + user-keying for `2fa-register-user`)
- `apps/api/src/auth/login/login.service.ts` + `apps/api/src/auth/refresh/refresh.controller.ts` (Rule-3 `epoch:0` stubs, subsequently overwritten by Plan 04)
- `apps/api/src/twofa/totp/totp.service.ts` (Rule-3 `void this.logger;` cross-plan unblock)
- `apps/api/package.json` + `pnpm-lock.yaml` (`@simplewebauthn/server@^11`, `@simplewebauthn/types@^11`)
- `.env.example` (5 new env vars: `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN`, `STEP_UP_TOKEN_TTL`, `TWOFA_REGISTER_RATE_LIMIT`, `TWOFA_WEBAUTHN_AUTH_RATE_LIMIT`)
- `packages/shared/src/error-codes.ts` (E1011..E1014)

---

## Next plans unblocked

- Wave 3: Plan 03-05 (sessions endpoints), Plan 03-06 (2FA-methods endpoints), Plan 03-07 (2FA-required guard) — all depend on Plans 02–04, all unblocked.
- Wave 4: Plan 03-08 (login branch) consumes `StepUpJwtService` from this plan + `Require2FAGuard` from 03-07.
