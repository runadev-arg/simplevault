# Access-Control Auditor — Phase 03 (2FA + Sessions)

- **Date:** 2026-05-04
- **Auditor:** access-control-auditor (NEW at this gate)
- **Mandate:** authorization correctness — owner-scoping, anti-enumeration on cross-user, step-up token containment, per-user session-epoch.
- **Mode:** read-only.
- **Verdict:** **PASS**

## Scope

Phase 03 routes audited:

- `GET /sessions`, `DELETE /sessions/:id`, `POST /sessions/revoke-all`
- `GET /2fa/methods`, `DELETE /2fa/methods/:id`
- `POST /2fa/webauthn/{begin,finish}-{register,auth}`
- `POST /2fa/totp/{begin,finish}-register`, `POST /2fa/totp/verify`
- `GET /2fa/step-up-material`
- `POST /vault/_2fa-guard-probe` (gated by `EXPOSE_TEST_ROUTES=1`)

## Per-route table

| Route | Guard chain | Owner-scope filter | Cross-user / not-found | Notes |
|---|---|---|---|---|
| `GET /sessions` | APP_GUARD `JwtAuthGuard` (epoch-checked) → class `JwtAuthGuard` | `WHERE user_id = ${userId}` (`session.service.ts:329`) + per-row family lookup also scoped `eq(userId, …)` (line 341) | n/a (list of own only) | Output Zod-parsed (defence-in-depth). |
| `DELETE /sessions/:id` | APP_GUARD `JwtAuthGuard` → `ParseUUIDPipe(v4)` | `revokeOne` SELECT scoped `eq(id) AND eq(userId)` (`session.service.ts:391-392`); UPDATE scoped on resolved `family_id` | **404** (`NotFoundException`, controller line 80) — uniform for cross-user, unknown id, already-revoked | Throws `AUTH_INVALID_CREDENTIALS` code via 404 envelope. Filter preserves status. No audit emit on null path (avoids enumeration oracle). PASS. |
| `POST /sessions/revoke-all` | APP_GUARD `JwtAuthGuard` | `WHERE user_id = ${userId}` SQL (`session.service.ts:437`); `bumpEpoch` updates only matching `users.id` | n/a | Bumps `users.session_epoch` then busts cache (correct ordering — line 264-267). Refresh cookie cleared. |
| `GET /2fa/methods` | APP_GUARD `JwtAuthGuard` + class `JwtAuthGuard` | `WHERE user_id = ${userId}` for both webauthn + totp queries (`methods.service.ts:87,98`); strict allowlist projection (id, name, createdAt, lastUsedAt only — no secret material) | n/a | Output Zod-parsed via `TwoFaMethodsListSchema.parse`. |
| `DELETE /2fa/methods/:id` | APP_GUARD `JwtAuthGuard` + class `JwtAuthGuard` → `ParseUUIDPipe(v4)` | DELETE scoped `eq(id) AND eq(userId)` for webauthn (`methods.service.ts:172-174`) and totp (`183-185`) | **404** (`NotFoundException`, controller line 87) — uniform for cross-user / unknown / removal-blocked-on-empty | Removal-guard 409 only fires when `before>0`; if user owns 0 methods, falls through to `remove()` → 404 (anti-enumeration preserved on empty inventory). PASS. |
| `POST /2fa/webauthn/begin-register` | APP_GUARD `JwtAuthGuard` + class `JwtAuthGuard` | service ops scoped to authed `userId` from `req.user.id`; challenge upserted with `(user_id, kind)` unique target | n/a | |
| `POST /2fa/webauthn/finish-register` | APP_GUARD `JwtAuthGuard` + class `JwtAuthGuard` | atomic `DELETE … WHERE user_id = ${userId} AND kind='register'` (`webauthn-register.service.ts:170`); credential row inserted with `userId` from `req.user.id` | n/a | |
| `POST /2fa/webauthn/begin-auth` | `@Public()` + `Require2FAStepUpGuard` | reads `req.stepUp.sub` (verified step-up); credentials filter `eq(userId, …)` (line 84) | n/a | Step-up token cannot be issued without prior 1FA pass. |
| `POST /2fa/webauthn/finish-auth` | `@Public()` + `Require2FAStepUpGuard` | atomic challenge consume scoped `WHERE user_id = ${userId} AND kind='auth'`; credential lookup scoped `eq(userId, …) AND eq(credentialId, …)` (lines 175-178) | n/a | Counter regression rejected (line ~218). Mints fresh access JWT with current epoch read fresh from DB. |
| `POST /2fa/totp/begin-register` | method-level `JwtAuthGuard` (also covered by APP_GUARD) | issuance nonce stored in Redis bound to `userId`; `boundUserId !== userId` rejects (line 131) | n/a | Server never sees plaintext secret. |
| `POST /2fa/totp/finish-register` | method-level `JwtAuthGuard` | INSERT bound to `req.user.id`; consumes the user-bound issuance nonce | n/a | |
| `POST /2fa/totp/verify` | `@Public()` + `Require2FAStepUpGuard` | atomic CAS `WHERE id = ${credentialId} AND user_id = ${userId} AND last_used_step < ${candidate}` (`totp.service.ts:182-187`) | uniform 401 `AUTH_2FA_TOTP_REPLAY` for wrong cred / wrong user / replay (line 193-196) | Anti-enumeration uniform error explicitly documented in code. |
| `GET /2fa/step-up-material` | `@Public()` + `Require2FAStepUpGuard` | reads `userId = req.stepUp.sub`; both queries scoped `eq(users.id, userId)` and `eq(totpCredentials.userId, userId)` | uniform 401 on user-deleted (anti-enumeration) | Returns the same wrap material `/auth/login` would yield post-1FA — no privilege escalation surface. |
| `POST /vault/_2fa-guard-probe` | method `@UseGuards(JwtAuthGuard, Require2FAGuard)` (also APP_GUARD `JwtAuthGuard` redundant) | `Require2FAGuard` rechecks `req.user.id` then counts methods | 401 if unauthed; 403 `AUTH_2FA_REQUIRED` if no 2FA | **Module gated by `EXPOSE_TEST_ROUTES === "1"` in `app.module.ts:162-164`** — production builds omit. Verified. |

## Per-gate-item findings

### Gate 1 — Only owner can list/revoke their own sessions
**PASS.** Every read/write in `session.service.ts` scoped on `req.user.id` (lines 329, 341, 391-392, 437). Cross-user requests cannot traverse the `user_id` predicate.

### Gate 2 — `DELETE /sessions/:id` returns 404 (NOT 403) on cross-user
**PASS.** `sessions.controller.ts:78-83` throws `NotFoundException` mapped through `AllExceptionsFilter` (`all-exceptions.filter.ts:22-43`) which preserves the 404 status and the embedded `error.code`. Service-level `revokeOne` returns `null` for cross-user / unknown / already-revoked — all collapsed to the same 404 envelope (`session.service.ts:395, 409`). No `ForbiddenException` is ever thrown on this path. No audit-emit on the not-found path (would itself become an enumeration oracle — explicit comment at `sessions.service.ts:43-48`). PASS.

### Gate 3 — `DELETE /2fa/methods/:id` returns 404 on cross-user
**PASS.** `methods.controller.ts:84-90` throws `NotFoundException` for both cross-user and unknown id. The removal-guard 409 only fires when `before>0` AND `countAfter===0` AND dep-stub returns true — so cross-user attempts (which yield `before === 0` for an attacker probing someone else's id) collapse to `remove()` returning `null` → 404 (`methods.service.ts:221-225`). PASS.

### Gate 4 — Session-epoch is per-user, not per-session
**PASS.** Column `users.session_epoch INT NOT NULL DEFAULT 0` (per `users.ts:76`). `bumpEpoch` updates `users.session_epoch` keyed on `users.id` only (`session.service.ts:265`). `revokeAllForUser` revokes every row `WHERE user_id = ${userId}` AND calls `bumpEpoch(userId)` — atomic kill of all access tokens for that user. Single-session revoke (`revokeOne`) deliberately does NOT bump epoch (correct — would invalidate sibling sessions; documented at `session.service.ts:378`). `JwtAuthGuard` reads `currentEpoch = epochCache.get(claims.sub)` and rejects mismatch as `AUTH_SESSION_REVOKED` (`jwt-auth.guard.ts:109-119`). PASS.

## Additional checks

- **Auth requirement applied (post-FINDING-0021).** APP_GUARD ordering verified at `app.module.ts:173-176`: `JwtAuthGuard` registered before `SimpleVaultThrottlerGuard`. `@Public()` opt-out present at every truly-public route (`/health`, `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/params`, `/invite/redeem`, all `/2fa/*` step-up routes, `GET /2fa/step-up-material`). Sessions + methods + 2fa-register controllers retain redundant class-level `@UseGuards(JwtAuthGuard)` — harmless, defence-in-depth.
- **Owner-scope filtering on every read/list.** Verified inline (table above).
- **Owner-scope mutation on every write.** Verified inline (table above) — every UPDATE/DELETE carries `eq(userId, …)`.
- **Step-up token containment.** `JwtAuthGuard` rejects any token where `payload.purpose !== undefined` BEFORE running `verifyAccessToken` (`jwt-auth.guard.ts:81-94`); `StepUpJwtService.verify` rejects anything where `payload.purpose !== "2fa-stepup"` (`step-up-jwt.service.ts:81-84`). Step-up tokens cannot be presented to `/sessions/*`, `/me`, `/2fa/methods`, or `/2fa/{webauthn,totp}/begin/finish-register`. PASS.
- **`POST /vault/_2fa-guard-probe` only exists when `EXPOSE_TEST_ROUTES=1`.** Verified at `app.module.ts:162-164` (conditional spread). Guard chain on the controller method: `JwtAuthGuard, Require2FAGuard` — without 2FA enrolled, returns 403 `AUTH_2FA_REQUIRED`; without auth, returns 401. Test-helpers module is gated by the same flag.

## Findings filed

None.

| ID | Severity | Title |
|----|----------|-------|
| —  | —        | (no Critical/High/Medium/Low findings; all four gate items + step-up containment + probe gating verified) |

Two informational observations (NOT findings — no remediation required, BY DESIGN per Phase 03 SUMMARY / 03-VERIFICATION):

1. **`methods.service.ts:32` — `userHasSharedVaultDependency` returns `false` unconditionally.** Documented Phase-07 hand-off seam (Key Link 7). Integration test injects a `() => true` stub to exercise the 409 path. Not a defect.
2. **TOCTOU between `countActive` and `remove` in `removeGuarded`** (`methods.service.ts:204-227`). Phase 03's stub always returns `false` so no real 409 race exists; documented inline that Phase 07 should wrap both queries in a single transaction when the dep helper becomes a real query. Not exploitable today.

## Verdict

**PASS.** All four blocking gate items satisfied with explicit code-line evidence. Anti-enumeration posture (uniform 404 on cross-user for both `DELETE /sessions/:id` and `DELETE /2fa/methods/:id`) is enforced both at the service layer (`null` return on every miss path) and at the controller layer (`NotFoundException` only — no `ForbiddenException` reachable). Per-user session-epoch correctly atomic. Step-up token containment enforced bidirectionally. Probe and test-helpers routes correctly gated by `EXPOSE_TEST_ROUTES`.

No Critical/High/Medium findings. No new entries required in `FINDINGS.md`. Phase-03 access-control gate is unblocked.

Report path: `.planning/security/audit-reports/2026-05-04-access-control-auditor-phase03.md`
