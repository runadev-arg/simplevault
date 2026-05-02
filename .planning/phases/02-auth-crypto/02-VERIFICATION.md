---
phase: 02
verified: 2026-05-02T00:00:00Z
verdict: PASS
status: passed
score: 12/12 must-haves verified
must_haves:
  truths:
    - "Operator can issue an invite for an email via `pnpm cli invite create --email <addr>`"
    - "User can hit /signup with a valid invite, generate three secrets client-side, and submit the 10-field signup envelope without any plaintext secret reaching the server"
    - "After signup, user is redirected to /login (NOT auto-logged-in)"
    - "From a fresh browser, user can log in with master pw + secret_key + email; access JWT in memory only; key store populated via byte-identical AAD labels matching signup"
    - "/me returns {id, email, createdAt, argon2Params} for an authed user, 401 otherwise"
    - "Refresh rotates: each /auth/refresh issues a new refresh + revokes the old; reuse → family revoke"
    - "Logout wipes client (always) + revokes server-side family"
    - "Timing-uniform errors on login miss (dummy Argon2id) and anti-enumeration on signup/login/invite"
    - "Cypress happy + sad path specs exist with the required assertions"
    - "CI `e2e` job exists and is configured (postgres 18.3-alpine + redis 7.4-alpine service containers, cypress:run, artifact upload)"
    - "All 12 plans (01-12) of phase 02 have SUMMARY.md indicating done; 02-PHASE-SUMMARY.md present"
    - "Operator runbook updates: argon2 calibration section, full env-var matrix, same-origin requirement, pre-cutover checklist"
  artifacts:
    - path: "apps/cli/src/commands/invite-create.ts"
      provides: "operator-side invite issuance (16B → Crockford base32 → HMAC-SHA256 → invite_codes row)"
    - path: "apps/api/src/auth/signup/signup.service.ts"
      provides: "atomic signup transaction (lock + insert user + redeem invite)"
    - path: "apps/api/src/auth/signup/signup.dto.ts"
      provides: "10-field strict envelope schema"
    - path: "apps/api/src/auth/login/login.service.ts"
      provides: "constant-time login with dummy-Argon2id timing floor"
    - path: "apps/api/src/auth/refresh/refresh.controller.ts"
      provides: "rotation + reuse-detect + family-revoke"
    - path: "apps/api/src/auth/logout/logout.controller.ts"
      provides: "family-revoke + cookie clear (idempotent)"
    - path: "apps/api/src/me/me.controller.ts"
      provides: "GET /me with JwtAuthGuard"
    - path: "apps/api/src/me/me.service.ts"
      provides: "MeResponseSchema-locked allow-list parse"
    - path: "apps/web/src/app/signup/page.tsx + steps/*"
      provides: "6-step wizard (invite, master pw, secret_key reveal/confirm, mnemonic reveal/confirm, submit)"
    - path: "apps/web/src/app/login/page.tsx"
      provides: "single-step login + AAD-byte-identical client crypto"
    - path: "apps/web/src/lib/crypto/aad-labels.ts"
      provides: "frozen AAD label prefixes shared by signup-derivations + login-derivations"
    - path: "apps/web/cypress/e2e/auth-happy.cy.ts + auth-sad.cy.ts"
      provides: "happy + sad path E2E specs"
    - path: ".github/workflows/ci.yml#e2e"
      provides: "postgres+redis service containers, cypress:run, screenshots/videos/logs upload on failure"
    - path: "docs/operator/SECURITY-NOTES.md + DOKPLOY-DEPLOY.md"
      provides: "argon2 calibration, env-var matrix, same-origin requirement, pre-cutover checklist"
gaps: []
---

# Phase 02 — Auth + Crypto core — Verification Report

**Phase Goal:** A user can redeem an operator-issued invite code, generate a master password + secret_key + 24-word recovery phrase client-side, sign up, log in from a fresh browser using all three secrets, and log out — with timing-uniform error handling and short-lived JWT + rotating refresh tokens.

**Verified:** 2026-05-02
**Status:** PASS (initial verification — no prior VERIFICATION.md)
**Score:** 12/12 truths verified

## Goal Achievement — Truth-by-Truth

### 1. Operator can issue an invite via `pnpm cli invite create --email <addr>` — VERIFIED

- `apps/cli/src/commands/invite-create.ts:25-64`: `inviteCreate({email, ttlDays})` → 16 random bytes → Crockford base32 → hyphenated code → `code_hash = HMAC-SHA256(SERVER_INVITE_SECRET, code_bytes)` → INSERT `invite_codes`. Single stdout emission of raw code.
- `apps/cli/src/main.ts` wires the subcommand under the binary `simplevault-cli`.
- 7-day default TTL (line 31), capped 1..365.

### 2. /signup posts 10-field envelope; no plaintext secret reaches the server — VERIFIED

- `apps/api/src/auth/signup/signup.dto.ts:51-72`: Zod `.strict()` schema accepts EXACTLY `inviteId, argon2SecretKeyHash, argon2Params, userArgonSalt, wrappedMasterDek, wrappedMasterDekRecovery, recoveryInnerHash, userPubKey, wrappedUserSigningSk, wrappedUserKxSk` (10 fields). Any extra key (e.g. `password`, `secret_key`, `recoveryPhrase`) is rejected with 400 BEFORE handler.
- `apps/web/src/app/signup/steps/SubmittingStep.tsx`: client runs `signupDerivations` then POSTs only the wrapped artifacts.
- DB schema `packages/db/src/schema/users.ts:9-28` documents and enforces no plaintext columns.

### 3. After signup, user redirected to /login (no auto-login) — VERIFIED

- `apps/web/src/app/signup/steps/SubmittingStep.tsx:81-95`: on 201 → `keyStore.wipe()` + `window.location.assign("/login?signed_up=1")`. NO token plumbed.

### 4. Fresh-browser login works; access JWT in memory; key store populated via byte-identical AAD labels — VERIFIED

- `apps/web/src/lib/crypto/aad-labels.ts:14-17`: 4 frozen labels (`sv:user-master:v1|`, `sv:user-recovery:v1|`, `sv:user-sign-sk:v1|`, `sv:user-kx-sk:v1|`).
- `apps/web/src/lib/crypto/signup-derivations.ts:152-167` and `login-derivations.ts:144-154` import the SAME constants — byte-equality guaranteed.
- `apps/web/src/lib/auth/access-token-store.ts:5-71`: in-memory only; never serialised.
- `apps/api/src/auth/login/login.service.ts:103-114`: 200 body returns `wrappedMasterDek`, salts, public key, wrapped private keys for client to unwrap.

### 5. /me returns the locked 4-field shape; 401 otherwise — VERIFIED

- `apps/api/src/me/me.controller.ts:11`: `@UseGuards(JwtAuthGuard)`.
- `apps/api/src/me/me.service.ts:43-52`: `{id, email, createdAt, argon2Params}` parsed via `MeResponseSchema.parse(...)` — extra keys throw → mapped to 500.

### 6. Refresh rotates; reuse triggers family-revoke + audit event — VERIFIED

- `apps/api/src/auth/refresh/refresh.controller.ts:21-102`: rotate → on `reuse` emit `AuditAction.RefreshReuseDetected` and 401.
- `apps/api/src/auth/sessions/session.service.ts:175-192`: `SELECT … FOR UPDATE` lock; if `used_at IS NOT NULL` → UPDATE all family siblings to `revoked_at = now()`, return `{kind: "reuse"}`.

### 7. Logout always wipes client + revokes server family — VERIFIED

- `apps/api/src/auth/logout/logout.controller.ts:19-55`: `revokeFamilyByToken` then ALWAYS clears the `__Host-refresh` cookie (idempotent, even on missing cookie).
- `apps/web/src/app/(authed)/me/page.tsx:60-67` + `auth-context.tsx`: `logout()` POSTs and ALWAYS wipes locally even if API call fails.

### 8. Timing-uniform errors + anti-enumeration — VERIFIED

- `apps/api/src/common/timing-floor.ts:25-41`: `dummyHash()` constant + `constantTimeEqual32`. NOT a setTimeout floor.
- `login.service.ts:75-82`: ALWAYS runs constant-time compare (verifier OR dummy) before deciding 401.
- `signup.service.ts:142-185`: invite-not-found / expired / already-redeemed / unique-email-violation ALL collapse to identical `AUTH_INVITE_INVALID` 400 body.
- Cypress sad-path `auth-sad.cy.ts:43-68` and `:102-137` assert `JSON.stringify(resA.body) === JSON.stringify(resB.body)` byte-equal.

### 9. Cypress happy + sad path specs — VERIFIED

- `apps/web/cypress/e2e/auth-happy.cy.ts` (129 lines): walks invite → signup wizard (6 steps, captures `secretKey` + `mnemonic` from DOM) → /me → logout → fresh login. Asserts `cy.assertNoSecretsInStorage()` at every checkpoint, asserts `__Host-refresh` cookie cleared after logout.
- `apps/web/cypress/e2e/auth-sad.cy.ts` (210 lines): byte-equal anti-enumeration probes (lines 43-68, 102-137); refresh-token reuse 401 (152-169); 12-burst rate-limit smoke → `429 + Retry-After` assertion (171-206).
- STATE.md gap: full local end-to-end Cypress run NOT exercised in this loop (documented in 02-12-SUMMARY); CI is the verification authority — accepted.

### 10. CI e2e job structurally correct — VERIFIED

- `.github/workflows/ci.yml:70-235`: `e2e` job, `needs: ci`, runs on PRs touching `apps/`, `packages/`, or workflows.
- Service containers: `postgres:18.3-alpine` (line 87) + `redis:7.4-alpine` (line 100), with healthchecks.
- Steps: install psql client, pnpm install, build, `pnpm db:migrate`, start API + web, poll `/health` and `/login`, `pnpm --filter @simplevault/web cypress:run`.
- Artifacts: cypress screenshots, videos, server logs uploaded on failure (lines 211-235).
- All required env vars present (JWT_SECRET, SERVER_INVITE_SECRET, SERVER_RECOVERY_HMAC_SECRET, SERVER_ARGON_SALT, etc.).

### 11. All 12 plans done; PHASE-SUMMARY present — VERIFIED

- `.planning/phases/02-auth-crypto/02-PHASE-SUMMARY.md`: present (243 lines), all 12 SUMMARYs marked DONE in plan map.
- Each plan's SUMMARY.md present (02-01-SUMMARY through 02-12-SUMMARY, line counts 5–18 KB each).

### 12. Operator runbook updates — VERIFIED

- `docs/operator/SECURITY-NOTES.md:94-130`: full Argon2id calibration section (one-time pre-cutover, target ~750ms, three env-vars to paste).
- `docs/operator/DOKPLOY-DEPLOY.md:64-167`: full Phase-02 env-var matrix; same-origin Traefik path-routing requirement explicitly documented (lines ~107, 160-167).
- `DOKPLOY-DEPLOY.md:168-203`: pre-cutover checklist with 6+ checkboxes (generate secrets / run argon2 calibrate / verify Traefik routes / issue first invite / walk signup wizard / verify auto-refresh / verify logout).
- `DOKPLOY-DEPLOY.md:240-280`: CLI reference (`invite create`, `argon2 calibrate`).

## Truth Table

| #  | Truth                                                                                | Result      | Evidence |
|----|--------------------------------------------------------------------------------------|-------------|----------|
| 1  | Operator can issue invite via CLI                                                    | VERIFIED    | apps/cli/src/commands/invite-create.ts:25-64 |
| 2  | 10-field signup envelope; no plaintext secret reaches server                         | VERIFIED    | apps/api/src/auth/signup/signup.dto.ts:51-72 + users.ts schema |
| 3  | Post-signup redirect to /login (no auto-login)                                       | VERIFIED    | SubmittingStep.tsx:81-95 (`window.location.assign("/login?signed_up=1")`) |
| 4  | Fresh-browser login; in-memory access JWT; AAD labels byte-equal                     | VERIFIED    | aad-labels.ts:14-17 + signup/login derivations imports |
| 5  | /me returns {id, email, createdAt, argon2Params}; 401 otherwise                      | VERIFIED    | me.controller.ts:11 + me.service.ts:43-52 (MeResponseSchema.parse) |
| 6  | Refresh rotates; reuse → family-revoke + audit event                                 | VERIFIED    | refresh.controller.ts + session.service.ts:175-192 |
| 7  | Logout wipes client always + revokes server family                                   | VERIFIED    | logout.controller.ts:19-55 + me/page.tsx logout button |
| 8  | Timing-uniform login miss (dummy Argon2id, NOT setTimeout) + anti-enum collapse      | VERIFIED    | timing-floor.ts:25-41 + login.service.ts:75-82 + signup.service.ts:142-185 |
| 9  | Cypress happy + sad specs with required assertions                                   | VERIFIED    | apps/web/cypress/e2e/auth-happy.cy.ts (129) + auth-sad.cy.ts (210) |
| 10 | CI e2e job structurally correct (pg 18.3 + redis 7.4 + cypress:run + artifacts)      | VERIFIED    | .github/workflows/ci.yml:70-235 |
| 11 | All 12 plans done; 02-PHASE-SUMMARY present                                          | VERIFIED    | .planning/phases/02-auth-crypto/02-{01..12}-SUMMARY.md + 02-PHASE-SUMMARY.md |
| 12 | Operator runbook updates (argon2 calibrate, env matrix, same-origin, pre-cutover)    | VERIFIED    | docs/operator/SECURITY-NOTES.md:94-130 + DOKPLOY-DEPLOY.md:64-203 |

## Anti-Patterns Found

None. No TODO/FIXME placeholders found in production paths. The only documented gap is the local Cypress run (02-12 SUMMARY explicitly defers to CI), and that is consistent with this phase's "Done when" clause (CI run is the verification authority).

## Recommendation

**CLOSE PHASE 02.**

All 12 truths verified at three levels (exists, substantive, wired). Ten-field strict signup envelope, atomic signup transaction with FOR UPDATE invite lock, dummy-Argon2id timing floor (not setTimeout), `__Host-refresh` cookie with Strict + HttpOnly + Secure, byte-identical AAD labels between signup and login derivations, family-revocation on refresh-token reuse, MeResponseSchema-locked /me, full Cypress specs with byte-equal anti-enumeration assertions, CI job with postgres 18.3-alpine + redis 7.4-alpine service containers and artifact upload, complete operator runbook with argon2 calibration + same-origin requirement + pre-cutover checklist.

Phase goal achieved. Hand off to security gate (`/gsd:verify-work 2` blocking auditors). Auditor sign-off in `.planning/security/AUDIT-LOG.md` is the remaining requirement before phase is fully closed.

---

_Verified: 2026-05-02_
_Verifier: Claude (gsd-verifier)_
