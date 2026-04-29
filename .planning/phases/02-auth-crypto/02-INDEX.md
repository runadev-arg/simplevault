# Phase 02 — Auth + Crypto core (Index + Wave Map)

**Goal (must be TRUE):** A user can redeem an operator-issued invite code, generate a master password + 128-bit secret_key + 24-word BIP-39 recovery phrase **client-side**, sign up, log in from a fresh browser using all three secrets, and log out — with timing-uniform error handling and short-lived JWT + rotating refresh tokens.

> **No 2FA in this phase.** Phase 03 owns WebAuthn + TOTP. This phase delivers password + secret_key + recovery-phrase as the auth surface.

## Goal-backward truths

For the goal to be TRUE, all of the following must be observable:

1. `pnpm cli invite create --email user@example.com` writes a single-use, 7-day TTL, HMAC-bound invite code to DB and prints the redemption code on stdout (operator delivers OOB; no SMTP in v1).
2. `POST /invite/redeem` exchanges a valid code → server returns `{ inviteId, email, argon2Params }` for the signup form to consume; the code is marked `redeemed_at` only after `POST /auth/signup` succeeds (atomic).
3. `POST /auth/signup` accepts a payload that contains email + `argon2_secret_key_hash` (server-side verifier) + `wrapped_master_dek` + `wrapped_master_dek_recovery` + `recovery_hmac` + `user_pub_key` (X25519) + `wrapped_user_signing_sk` + `wrapped_user_kx_sk` + Argon2 params; server NEVER sees the master password, the secret_key, or the recovery phrase.
4. The web `/signup` flow forces the user to (a) generate + display the secret_key, (b) generate + display the BIP-39 24-word phrase, (c) re-enter selected words to confirm transcription before the account is created — confirmation gate cannot be bypassed by enabling buttons in devtools (server rejects signup unless the client posted the phrase-derived `recovery_hmac` matching the wrap).
5. `POST /auth/login` from a fresh browser, given correct (email + master_password + secret_key), returns 200 with a short-lived access JWT (15 min, HS256) + a `__Host-refresh` httpOnly+Secure+SameSite=Strict cookie (30 day TTL, single-use).
6. `POST /auth/login` returns the **identical** response shape, status, and timing distribution for: (a) email not found, (b) wrong password, (c) wrong secret_key, (d) correct credentials. Timing floor enforced via constant-time dummy `Argon2id` on miss (NOT a `setTimeout`).
7. `POST /auth/refresh` rotates the refresh token: old token marked `used_at`, new token issued in the same family. Replaying a previously-rotated refresh token revokes the entire session family AND emits a `auth.refresh.reuse_detected` log event (Phase 10 will turn this into an audit-log row + alert).
8. `POST /auth/logout` revokes the current session family (sets `revoked_at` on all sessions sharing the `family_id`) and clears the refresh cookie.
9. `GET /me` returns user metadata only (`id`, `email`, `created_at`, `argon2_params`) — NEVER `argon2_secret_key_hash`, NEVER any wrapped DEK, NEVER `recovery_hmac`, NEVER any private key material.
10. Login + signup + refresh endpoints are rate-limited per REQ-RATELIMIT-002..003: login 5/IP/15min + 10/email/15min sliding window; signup 3/IP/hour. Verified by sending the (N+1)th request and getting `429` with `Retry-After`.
11. Server stores ONLY: `argon2_secret_key_hash` + `argon2_params` + `wrapped_master_dek` + `wrapped_master_dek_recovery` + `recovery_hmac` + public keys + wrapped private keys. Schema enforces: NO column for `master_password`, `secret_key`, plaintext `master_dek`, plaintext `recovery_phrase` — verified by inspecting the migration SQL.
12. `pnpm test` in `packages/crypto` exercises Argon2id round-trip, XChaCha20-Poly1305 encrypt/decrypt with AAD, BIP-39 generate/validate, key-hierarchy derive→wrap→unwrap, and X25519 sealed-box round-trip — all green in both Node and browser (jsdom or happy-dom) test environments.
13. Cypress (or Playwright) E2E test: invite-create → signup-with-recovery-confirm → logout → login-fresh-browser → `/me` shows user → logout. Sad path: wrong secret_key on login → indistinguishable error + indistinguishable timing.

## Required artifacts (high level)

- `packages/crypto/src/`: real impl modules — `argon2id.ts`, `aead.ts`, `bip39.ts`, `key-hierarchy.ts`, `sealed-box.ts`, `calibrate.ts`, plus tests under `packages/crypto/test/`. Conditional exports map preserved (browser/node). No Node `crypto` import in browser bundle.
- `packages/db/src/schema/`: extended `users.ts`, new `user_sessions.ts`, new `invite_codes.ts`, new barrel entries, generated Drizzle migration (`drizzle/0001_*.sql`).
- `apps/api/src/`: `auth/` module (signup, login, logout, refresh controllers + services + DTOs with Zod), `invite/` module (redeem), `me/` module, `crypto/` module (Argon2id verifier wrapping `@simplevault/crypto/node`), `common/` (timing-floor guard, JWT strategy, refresh-token guard, rate-limit guard via `@nestjs/throttler@^6`), updated Pino redaction list.
- `apps/web/src/app/`: `signup/page.tsx` (multi-step: invite code → master password → secret_key reveal → recovery phrase reveal → confirmation challenge → submit), `login/page.tsx`, `logout/route.ts`, `lib/auth/` (token storage in memory only, auto-refresh hook).
- `apps/cli/`: new workspace package with one binary `simplevault-cli` and the `invite create` subcommand; consumes `@simplevault/db` directly.
- E2E suite: `apps/web/cypress/` (or `apps/web/e2e/` if Playwright) with happy + sad path specs.
- NestJS upgrade: 10.4.x → 11.x; `pnpm.overrides` for `multer@<2.1.1` removed.

## Key links (where this most likely breaks)

1. **Argon2id calibration drift** — calibrate on prod hardware (Dokploy VPS), not local dev. Phase ships a CLI tool the operator runs once on the VPS; Phase-02 default fallback values are the conservative `m=64MiB, t=3, p=1` from CRYPTO-STACK.md. Operator MUST set `ARGON2_TIME_COST` + `ARGON2_MEMORY_COST` env vars in Dokploy before production cutover (flagged in operator runbook update by Plan 12). If the calibrated values are baked into a user record at signup, every device for that user MUST use the same params — server is authoritative.
2. **`packages/crypto` browser bundle** must NOT pull in Node `crypto`. The exports map handles this; verify post-build with a Webpack/Vite-style resolution probe or by grepping `dist/browser.js` for `require("crypto")` / `from "node:crypto"`. Regression here = silent ~500KB bloat or a "crypto is not defined" runtime error in the web bundle.
3. **Server stores `Argon2id(secret_key, server_salt)` only** — NEVER the raw `secret_key`, NEVER the master password, NEVER any plaintext KEK or DEK. Schema review must enforce: no column named `secret_key`, `master_password`, `password_hash` (the verifier is `argon2_secret_key_hash` to make the role explicit).
4. **Recovery phrase NEVER touches the server.** Server stores only `recovery_hmac = HMAC(server_secret, sha256(phrase))` and `wrapped_master_dek_recovery`. Document this in every signup/recovery PLAN. Recovery itself ships in Phase 11; this phase only emits + stores the artifacts.
5. **`/me` MUST NOT expose** the user's wrapped DEK material, `argon2_secret_key_hash`, `recovery_hmac`, or any wrapped private-key blob — only profile metadata. `auth-flow-auditor` will flag this.
6. **Refresh-token rotation race** — store hash (BLAKE2b-256), not raw token. `family_id` + `prev_token_id` per session lineage. Reuse detection: if a `used_at IS NOT NULL` token is presented, revoke the entire family AND log `auth.refresh.reuse_detected`. Use a Postgres `SELECT … FOR UPDATE` (or unique-index-driven INSERT-as-rotation pattern) to make rotation atomic under concurrent refresh.
7. **Timing-floor leak** — use a constant-time `Argon2id` dummy run on miss. NEVER a `setTimeout(...)` floor — measurable through Promise scheduling. Never branch on `user === null` *before* the Argon2id call; structure code so every login path runs Argon2id exactly once.
8. **Pino redaction list extension** — add: `secretKey`, `secret_key`, `recoveryPhrase`, `recovery_phrase`, `masterPassword`, `master_password`, `masterPasswordHash`, `argon2idHash`, `argon2_secret_key_hash`, `argon2SecretKeyHash`, `dek`, `kek`, `nonce` (the crypto nonce — note: do NOT redact `req.headers['x-csp-nonce']` because that's the CSP nonce; namespace carefully), wrapped key fields, `req.headers.authorization`, `res.headers['set-cookie']`, `req.body.token`, `req.body.refreshToken`, plus the existing list.
9. **NestJS 10 → 11 upgrade** — must land first (Wave 1). Removes the `pnpm.overrides` for `multer@<2.1.1` and clears the dev-only `@nestjs/cli@10.4.9` glob/picomatch Highs. Don't try to upgrade simultaneously with new feature work.
10. **`@simplevault/crypto` exports map regression** — when adding new modules (argon2id, aead, bip39, key-hierarchy, sealed-box), they MUST be re-exported through both `browser.ts` and `node.ts` barrels with identical TypeScript types so the API surface is platform-agnostic. Add a CI check (or at minimum a Plan-04 verification step) that compares the exported symbol set across the two entrypoints.
11. **Audit log future-proofing** — Phase 10 builds the HMAC-chained audit log. Phase 02 must already emit structured Pino events (`auth.signup.ok`, `auth.login.ok`, `auth.login.fail`, `auth.logout`, `auth.refresh.ok`, `auth.refresh.reuse_detected`, `invite.redeem.ok`, `invite.redeem.fail`) with the right metadata shape (actor_user_id, ip_hash, user_agent_family, action_type, target_id, outcome) so Phase 10 can append-only-link them later. **Do NOT build the audit-log table or chain in Phase 02.**
12. **JWT secret rotation** — `JWT_SECRET` (HS256) in env. Plan structure includes a `kid` header field so a future rotation can be supported without forced re-login. Phase 02 ships single-key; rotation runbook is Phase 14.

## Wave map (parallel execution)

```
Wave 1 ──► Plan 01 (NestJS 10→11 upgrade + remove multer override)
            │
Wave 2 ──┬► Plan 02 (crypto: Argon2id calibration + AEAD helpers)  [TDD]      ┐
         ├► Plan 05 (DB schema: users extend + sessions + invite_codes)        │
         └► Plan 03 (crypto: BIP-39 + key hierarchy)                  [TDD]    ┘ ← parallel (3 tracks)
            │
Wave 3 ──┬► Plan 04 (crypto: X25519 sealed-box + cross-runtime export check) [TDD] ┐
         └► Plan 06 (operator CLI: pnpm cli invite create)                          ┘ ← parallel
            │
Wave 4 ──┬► Plan 07 (API: POST /invite/redeem + POST /auth/signup)             ┐
         │                                                                     │
         │   (Plan 08 also Wave 4 — different files, no shared module state)   │
         └► Plan 08 (API: /auth/login + /auth/refresh + /auth/logout)          ┘ ← parallel
            │
Wave 5 ──► Plan 09 (API: GET /me + Pino events for audit + rate-limit guards)
            │
Wave 6 ──┬► Plan 10 (Web: /signup multi-step flow with confirmation gates)     ┐
         └► Plan 11 (Web: /login + auto-refresh hook + logout)                 ┘ ← parallel
            │
Wave 7 ──► Plan 12 (E2E happy + sad path + operator runbook update for Argon2 calibration)
```

12 plans, 7 waves. Sequential time = 12×; parallel time ≈ 7×. Saves ~42%.

**TDD plans (`type: tdd`):** 02, 03, 04 — the crypto package. RED→GREEN→REFACTOR for each primitive; round-trip tests are the contract.

## Operator decisions surfaced

- **SMTP provider** — DEFERRED to Phase 07 (sharing/invites). Phase 02 v1 invite delivery is **out-of-band**: operator runs `pnpm cli invite create --email <addr>`, the CLI prints the code on stdout, and the operator hand-delivers it to the user (Signal, in-person, or operator's own email client). Email field on the invite is a binding identifier, not a delivery target. Rationale: removes a Phase 02 prerequisite (SMTP provider choice + deliverability config) without affecting the security model. Operator may override this and pull SMTP forward into Phase 02 by raising the question; otherwise it stays Phase 07.
- **Argon2id calibration** — operator MUST run the `pnpm cli argon2 calibrate` tool ONE TIME on the production VPS (Dokploy host) before going live, then set `ARGON2_TIME_COST` + `ARGON2_MEMORY_COST` as Dokploy env vars. Phase-02 default fallback if env unset = `m=64MiB, t=3, p=1` (conservative). The calibrator targets ~750ms wall time (per CRYPTO-STACK.md §2). Documented in `docs/operator/SECURITY-NOTES.md` update at Plan 12.
- **JWT_SECRET** — operator MUST generate a 256-bit random value and set `JWT_SECRET` in Dokploy env-var UI before deploy. Phase 02 startup fails fast if `JWT_SECRET` is missing or shorter than 32 bytes (constant-time check).
- **Operator-account 2FA** — still open (Phase 14 decision per STATE.md). NOT a Phase 02 blocker.

## Security gate (blocks completion of this phase)

Run via `/gsd:verify-work 2`:

| Auditor | What it must verify | Blocking? |
|---|---|---|
| `crypto-auditor` | Argon2id params + calibration boundaries; AEAD AAD binding (KDF params + record metadata); two-secret invariants (server never sees password/secret_key/recovery); BIP-39 derivation matches spec; constant-time comparisons via `sodium.memcmp` / `crypto.timingSafeEqual`; nonce-generation uses `randombytes_buf(24)`; key hierarchy round-trip; recovery flow stores only HMAC; KDF param downgrade defended via AAD bind | YES |
| `auth-flow-auditor` | Signup invite-code single-use; login uniform error + uniform timing (timing-floor via dummy Argon2id, NOT setTimeout); refresh rotation single-use; family revocation on reuse-detect; logout revokes family; `/me` doesn't leak verifier or wrapped material; account enumeration neutralised across signup + login + refresh | YES |
| `owasp-top10-auditor` | A01 broken access control (route guards on /me + /auth/* + /invite/*), A02 crypto failures (KDF params, AEAD, RNG), A07 auth failures focus | YES |
| `input-validation-auditor` | Zod on every DTO with `.strict()`; no SQL injection (Drizzle parameterised); no prototype pollution via JSON parser; size limits on bodies | YES |
| `rate-limit-dos-auditor` | REQ-RATELIMIT-002 (login 5/IP/15min + 10/email/15min sliding window), REQ-RATELIMIT-003 (signup 3/IP/hour), refresh + invite-redeem rate-limited; backed by Redis token-bucket via `@nestjs/throttler@^6`; verified by burst test | YES |
| `threat-modeler` | Updates Login flow STRIDE + AT-5 (privilege-escalate); refreshes M0 baseline §2 Login + §10 Auth row | Informational (does not block, but must be updated) |

Phase 02 is **complete** when:
1. All 12 plans show ✅ in `STATE.md`.
2. All 13 goal-backward truths verified.
3. All 5 blocking auditors PASS in `.planning/security/AUDIT-LOG.md` with no Critical/High open in `FINDINGS.md`.
4. `threat-modeler` Phase-02 update committed.
5. Cypress (or Playwright) happy + sad E2E green in CI.

## Execution

After reviewing this index, execute with `/gsd:execute-phase 2`. The execute-phase orchestrator will:
- Run Wave 1 (Plan 01: NestJS 11 upgrade) → wait → Wave 2 (Plans 02 + 03 + 05 parallel) → ... → Wave 7 (Plan 12 E2E + runbook).
- Each plan commits atomically (`feat(02-NN-T<M>): ...`).
- TDD plans (02/03/04) commit RED→GREEN→REFACTOR separately.
- After Wave 7, automatically suggest `/gsd:verify-work 2` to run the 5-auditor gate.
