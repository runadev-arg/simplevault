---
phase: 03-2fa-sessions
plan: 03
type: tdd
subsystem: twofa-totp
tags: [tdd, totp, rfc-6238, browser-only, replay-guard, cas, libsodium, noble-hashes]
requires:
  - 03-01 (totp_credentials table + users.session_epoch column)
  - 03-02 (Require2FAStepUpGuard + StepUpJwtService — verify route depends on it)
  - 03-04 (epoch claim on AccessTokenClaims — verify endpoint mints epoch-bearing JWT)
provides:
  - browser-only RFC 6238 helpers (computeTotpStep / verifyTotpCandidate / buildOtpauthUrl + totpReady)
  - POST /2fa/totp/begin-register (auth-JWT-gated)
  - POST /2fa/totp/finish-register (auth-JWT-gated)
  - POST /2fa/totp/verify (step-up-token-gated; mints full session)
  - server-opaque wrapped-secret persistence pattern (zero RFC 6238 server-side)
  - atomic CAS replay guard (UPDATE ... WHERE last_used_step < $cs RETURNING id)
affects:
  - 03-08 (auth/login extension — branch on 2FA presence reads totp_credentials)
  - 03-10 (web /settings/security — TotpRegisterSchema is the contract)
  - 03-12 (E2E Cypress 2fa-totp.cy.ts will drive begin → finish → verify against this controller)
tech-stack:
  added:
    - "@noble/hashes (already a crypto-package dep) — used here for HMAC-SHA-1 (libsodium-wrappers-sumo intentionally drops crypto_auth_hmacsha1)"
  patterns:
    - "Browser-only crypto module (totp.ts) re-exported ONLY from packages/crypto/src/browser.ts; absent from node.ts barrel; parity-test snapshot enforces"
    - "Issuance-nonce + Redis GETDEL for begin→finish atomicity (TTL 120s, NX, sha256(nonce) as key)"
    - "Atomic compare-and-swap replay guard: single UPDATE … WHERE last_used_step < $cs RETURNING id; zero rows -> 401"
    - "Registration-step burn: finish-register seeds last_used_step = candidateStep so the enrolment code is also burned"
    - "Constant-time drift-window scan: verifyTotpCandidate walks the full 2*drift+1 window even after a hit"
key-files:
  created:
    - packages/crypto/src/totp.ts
    - packages/crypto/test/totp.test.ts
    - apps/api/src/twofa/totp/totp.controller.ts
    - apps/api/src/twofa/totp/totp.service.ts
    - apps/api/src/twofa/totp/totp.dto.ts
  modified:
    - packages/crypto/src/browser.ts (re-export totp.ts surface)
    - packages/crypto/test/parity.test.ts (snapshot: +buildOtpauthUrl, computeTotpStep, totpReady, verifyTotpCandidate as browser-only)
    - packages/shared/src/zod/index.ts (TotpBeginRegisterResponseSchema, TotpFinishRegisterSchema, TotpVerifySchema, TotpFinishRegisterResponseSchema)
    - packages/shared/src/error-codes.ts (E1015 AUTH_2FA_TOTP_REPLAY, E1016 AUTH_2FA_TOTP_ISSUANCE_INVALID)
    - apps/api/src/twofa/twofa.module.ts (register TotpController + TotpService)
    - apps/api/src/common/audit-events.ts (auth.2fa.totp.{register,verify}.{ok,fail})
    - apps/api/src/common/throttler.config.ts (twoFaVerifyIp 30/min IP-keyed)
duration: ~30min
completed: 2026-05-02
---

# Phase 03 Plan 03: TOTP API + browser-only crypto Summary

RFC 6238 TOTP enrolment + verification, browser-only crypto, atomic replay guard. The server stores only the wrapped secret blob + AAD bytes — it never sees the plaintext 20-byte secret and runs ZERO RFC 6238 arithmetic.

**Status:** COMPLETE
**Date:** 2026-05-02
**Commits:** `645c00f` (T1 RED — bundled into 03-02-T1 by sibling-plan staging; see Deviations §1), `4ea3e73` (T2 GREEN), `ca13403` (T3 API)
**Tasks:** 3/3

---

## What landed

### Task 1 (RED) — `test(03-03-T1): RFC 6238 vectors + round-trip + drift expectations` (bundled into `645c00f`)

`packages/crypto/test/totp.test.ts` — 18 deterministic Vitest cases covering:

- **RFC 6238 Appendix B vectors (SHA-1)** at `t = 59 / 1111111109 / 1234567890 / 2000000000` pinned for both 6-digit form (`287082`, `081804`, `005924`, `279037`) and 8-digit form (`94287082`, `07081804`, `89005924`, `69279037`). Future regressions in the dynamic-truncation step localise to a single vector.
- **Round-trip** — `computeTotpStep(s, 100)` then `verifyTotpCandidate(s, code, 100, 1).step === 100`.
- **Drift window** — code from step 100 verified at step 99 / 101 with `drift=1` → ok; at step 98 / 102 → false. (The window MUST be exactly `[currentStep - drift, currentStep + drift]`.)
- **Wrong secret** — code from a different secret, same step, drift=1 → false.
- **Strict format guards** — 5/7-digit input, non-numeric, empty string → all false. The verifier accepts only `/^\d{6}$/`.
- **`buildOtpauthUrl` canonical output** — `otpauth://totp/SimpleVault%3Aalice%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=SimpleVault&algorithm=SHA1&digits=6&period=30` with override-period and override-digits paths covered.
- **Browser-only barrel surface** — `import("../src/browser.js")` exports the four totp functions; `import("../src/node.js")` does not. The parity-test snapshot is updated so any future drift (someone re-exporting from node.ts) fails the parity suite, not just this file.

`packages/crypto/src/totp.ts` initial stub throws `"not implemented"` on every public function; T1 commit ran 18 reds + 73 greens (parity + browser-only barrel surface checks pass against the stub because the surface is correct, behaviour is not).

### Task 2 (GREEN) — `feat(03-03-T2): packages/crypto/totp.ts implementation + browser-only export` (`4ea3e73`)

Real RFC 6238 / RFC 4226 implementation in `packages/crypto/src/totp.ts`:

- **HMAC-SHA-1 via `@noble/hashes`.** libsodium-wrappers-sumo does NOT expose `crypto_auth_hmacsha1` — sumo's HMAC bindings are SHA-256, SHA-512, and SHA-512/256 only. The libsodium native library has the primitive; the JS wrapper drops it as "deprecated for new construction". Switching the entire vault to noble for HMAC would be a wider change; for THIS one RFC-mandated SHA-1 use we pull `hmac` + `sha1` from `@noble/hashes` (already a `@simplevault/crypto` dep, audited Cure53 2024, pure JS, browser-safe). The file header documents this as the project's ONLY SHA-1 use; do not propagate.
- **Dynamic truncation** per RFC 4226 §5.3: `offset = mac[19] & 0x0f`; the next four bytes are masked (`b0 & 0x7f` for the high-bit) and assembled big-endian into a 31-bit unsigned int; `value mod 10^digits`, zero-padded.
- **`verifyTotpCandidate`** walks the full `2*drift + 1` window EVEN AFTER A HIT (always computes `2*drift + 1` codes, calls `sodium.memcmp` on each, only assigns `matchedStep` once). This makes the wall-time uniform across the drift slots — an attacker who can race the API cannot tell which slot matched. Also rejects any code that's not strictly `/^\d{6}$/` BEFORE the loop, and skips negative-step iterations (`step < 0` continue) so very-early-clock callers don't blow up.
- **`buildOtpauthUrl`** uses an inline RFC-4648-no-pad base32 encoder (~20 lines, no extra dep). Output is canonical: `otpauth://totp/<issuer>:<account>?secret=<b32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30` (override-able digits/period).
- **`totpReady()`** exported so the web bundle can pre-warm the libsodium WASM (`sodium.memcmp` is the only libsodium-touching primitive in this module). Surface is in the parity snapshot under the browser-only set.

`packages/crypto/src/browser.ts` adds a single line: `export * from "./totp.js"`. `packages/crypto/src/node.ts` does NOT re-export — server-side TypeScript code that tries to `import { computeTotpStep } from "@simplevault/crypto/node"` fails to compile.

`packages/crypto/test/parity.test.ts` — the `BROWSER_ONLY_EXPECTED` snapshot grows by four entries (`buildOtpauthUrl`, `computeTotpStep`, `totpReady`, `verifyTotpCandidate`); the `NODE_ONLY_EXPECTED` and `SHARED_EXPECTED` sets are unchanged. Any future edit that re-exports a totp helper from `node.ts` triggers the parity test, not just a runtime test.

Verify gate: `pnpm --filter @simplevault/crypto build && pnpm --filter @simplevault/crypto test` — 91 tests green (73 prior + 18 new). `grep -E "from \"node:|require\(.crypto" packages/crypto/src/totp.ts` returns nothing. `pnpm --filter @simplevault/web build` green (no Node-only import bleeds into the web bundle).

### Task 3 — `feat(03-03-T3): /2fa/totp/{begin,finish}-register + /verify with atomic replay guard` (`ca13403`)

Three new files under `apps/api/src/twofa/totp/`:

- **`totp.dto.ts`** — re-exports the four Zod schemas from `@simplevault/shared/zod` (`TotpBeginRegisterResponseSchema`, `TotpFinishRegisterSchema`, `TotpFinishRegisterResponseSchema`, `TotpVerifySchema`) plus the matching types. Single import path inside the API package.
- **`totp.service.ts`** — three methods on a single `@Injectable()` class:
  - `beginRegister(userId)`: generates a 32-byte random `issuanceNonce` (base64url), hashes it (`sha256`) into a Redis key `totp:issuance:<hashB64Url>` with `SET ... EX 120 NX` so a collision can't silently overwrite an in-flight enrolment, and returns `{issuanceNonce}`.
  - `finishRegister(userId, dto)`: runs Redis `GETDEL` on the same key (Redis 6.2+ atomic; Dokploy ships Redis 7); if the bound user-id is missing or doesn't match → 400 `AUTH_2FA_TOTP_ISSUANCE_INVALID` (E1016). On success, INSERTs the row with `last_used_step = candidateStep` (the registration-step burn — see §"Decisions" below). Returns `{id, name}`.
  - `verify(userId, dto)`: ATOMIC CAS — `UPDATE totp_credentials SET last_used_step = $cs, last_used_at = now() WHERE id = $cid AND user_id = $uid AND last_used_step < $cs RETURNING id`. Zero rows → 401 `AUTH_2FA_TOTP_REPLAY` (E1015). One row → returns `{credentialId}` to the controller, which mints the full session.
- **`totp.controller.ts`**:
  - `POST /2fa/totp/begin-register` — `@UseGuards(JwtAuthGuard)`, rate-limit `2fa-register-user` (Plan 02-T1's user-keyed ceiling, 10/min default).
  - `POST /2fa/totp/finish-register` — same guard + ceiling. Audits `auth.2fa.totp.register.{ok,fail}`.
  - `POST /2fa/totp/verify` — `@UseGuards(Require2FAStepUpGuard)` (Plan 02-T1's step-up-token gate), rate-limit `2fa-verify-ip` (NEW, 30/min IP-keyed). On success, fetches the user's wrapped material + `session_epoch` from `users`, calls `SessionService.createOnLogin` + `JwtService.signAccessToken` with `{sub, sid, fam, epoch}`, sets the `__Host-refresh` cookie, and returns the same body shape as `/auth/login` 1FA-only success (so the web client's discriminated handler treats it identically). Audits `auth.2fa.totp.verify.{ok,fail}`.

`apps/api/src/twofa/twofa.module.ts` extended (Plan 02-T1 created the module): adds `TotpController` to the controllers list and `TotpService` to the providers/exports lists.

**Verify gates:**

- `pnpm --filter @simplevault/api build` green.
- `pnpm --filter @simplevault/crypto test` green (91 tests).
- `pnpm --filter @simplevault/web build` green.
- Server-side grep cleanliness:
  - `grep -rE 'master_(DEK|KEK|kek|dek)' apps/api/src/twofa/totp/` → empty.
  - `grep -rnE 'computeTotpStep|verifyTotpCandidate|buildOtpauthUrl' apps/api/src/` → matches only a comment in `totp.service.ts` that asserts the invariant; ZERO real imports.
  - The TOTP browser helpers cannot be imported from `@simplevault/crypto/node` (parity test enforces).
- ESLint clean for all files in this plan (existing webauthn lint errors are Plan 02 territory).

---

## Truths verified

| # | Truth (from 03-INDEX) | Status |
|---|---|---|
| 5 | `POST /2fa/totp/begin-register` returns issuance-nonce only; server NEVER sees the plaintext secret | OK — controller returns `{issuanceNonce}`; service never imports any crypto/browser symbol |
| 6 | `POST /2fa/totp/finish-register` accepts `{wrappedSecret, encryptedSecretAad, name, candidateStep}`; INSERTs `totp_credentials` with `last_used_step = candidateStep`; returns `{id, name}` | OK — controller validated by `TotpFinishRegisterSchema`, service issues the INSERT, `lastUsedStep: dto.candidateStep` |
| 7 | `POST /2fa/totp/verify` runs atomic `UPDATE ... WHERE last_used_step < $cs RETURNING *`; zero rows → 401 `AUTH_2FA_TOTP_REPLAY`; one row → mint full session | OK — `TotpService.verify` SQL exact form; controller mints session via `SessionService.createOnLogin` + `JwtService.signAccessToken` (with epoch claim from Plan 04-T2) |

Truth 8 (`/auth/login` branch on 2FA presence) is Plan 03-08's job; this plan only ships the destination of the step-up flow. Truth 9–10 (`/2fa/methods` + `DELETE /2fa/methods/:id`) are Plan 03-06.

---

## Decisions Made

1. **HMAC-SHA-1 via `@noble/hashes`, NOT libsodium.** libsodium-wrappers-sumo doesn't expose `crypto_auth_hmacsha1` — sumo's HMAC bindings are SHA-256/512/512-256 only. noble is already a `@simplevault/crypto` dep (audited Cure53 2024) and pure JS, so adding SHA-1 here adds zero bytes to the bundle and zero new supply-chain trust. Documented in the file header as the project's ONLY SHA-1 use site; do not propagate.
2. **`totpReady()` exported alongside the three computational helpers.** `verifyTotpCandidate` uses `sodium.memcmp` for constant-time compare (matches the rest of the project's CT-compare pattern); the web bundle should pre-warm libsodium once at app boot. This is a fourth public symbol (the plan listed three) — added to the parity-test browser-only snapshot.
3. **Constant-time drift-window scan.** `verifyTotpCandidate` walks the full `2*drift + 1` slots even after a hit. An attacker racing the API cannot use timing to discern WHICH drift slot matched. Cost is negligible (3 HMAC-SHA-1 ops on a 20-byte secret) and the security benefit is real for a phone-only-vulnerable-to-phishing 2FA factor.
4. **Issuance nonce stored as `sha256(nonce)`-keyed Redis entry, not the raw nonce.** Pre-image resistance is the property we want; we never compare nonces directly (we just `GETDEL`). A Redis dump never yields the live token. TTL=120s (matches Truth 5's ceremony budget); `NX` so a collision can't silently overwrite. `GETDEL` is atomic on Redis 6.2+; Dokploy ships Redis 7.
5. **Registration-step burn at finish-register time.** Insert `last_used_step = dto.candidateStep` so the very 6-digit code the user typed at enrolment time is also burned at `/verify`. An attacker who reads the finish-register POST cannot replay its `candidateStep`. Costs nothing — the column was going to start at 0 by default; we just bump it to the proven step.
6. **Anti-enumeration on `/verify`.** The CAS WHERE clause includes `eq(userId, $uid)` so a step-up token bound to user A cannot consume user B's credential. Zero-rows-updated covers wrong credentialId, wrong userId, AND replay — same uniform 401 either way (anti-enumeration).
7. **`/verify` returns the same body shape as `/auth/login` 1FA-only success** (accessToken + wrapped material + argon2 params + per-user salt). The web client's discriminated `{kind:"session"}` branch handles it identically — no parallel parser needed. Cookie set with the SAME `__Host-refresh` flags.
8. **Bounded base64 schemas (not exact-length).** `wrappedSecret` is `36..128` bytes (20 secret + 16 Poly1305 tag minimum, headroom for any future scheme bump); `encryptedSecretAad` is `16..256` bytes. Loose enough to permit the documented AAD shape (16-byte label + 32-byte sha256(email) + 24-byte nonce = 72 bytes) without being trivially permissive.
9. **`twoFaVerifyIp` as a NEW IP-keyed ceiling.** `/verify` is a step-up-token-bearer route — no `req.user` yet, so user-keying is unavailable. 30/min IP-keyed matches `login-ip`'s order of magnitude.
10. **Error codes E1015 + E1016.** Plan 02-T1 claimed E1011..E1014; this plan adds E1015 (`AUTH_2FA_TOTP_REPLAY`) + E1016 (`AUTH_2FA_TOTP_ISSUANCE_INVALID`). Plan-prescribed `E1011` for replay was unavailable.

---

## Performance budget (verify endpoint)

The `/2fa/totp/verify` server path is **one INSERT-equivalent SQL UPDATE + one row of `users` SELECT + one cookie + one JWT sign**. No Argon2id (the user already passed 1FA). No client-side derivation. No HMAC-SHA-1 (the server runs zero RFC 6238 arithmetic). Expected p99 well under 30 ms on Postgres 18.3 + Dokploy local Redis. Plan 03-04's epoch-cache adds a Redis read on the next authed request, not on `/verify` itself.

---

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 3 — Blocking] HMAC-SHA-1 not in libsodium-wrappers-sumo.**

- Found during: T2 GREEN.
- Issue: Plan said to use `sodium.crypto_auth_hmacsha1`. Runtime error: `default.crypto_auth_hmacsha1 is not a function`. Verified by enumerating `sodium` keys after `await sodium.ready` — only SHA-256/512/512-256 HMAC bindings are present.
- Fix: switched to `@noble/hashes` `hmac(sha1, key, msg)`. noble was already a crypto-package dep, so no new dependency. File header updated to document the choice + reaffirm it as the project's only SHA-1 site. No public-API change.
- Files modified: `packages/crypto/src/totp.ts`.
- Commit: `4ea3e73`.

**2. [Rule 2 — Missing critical] Plan listed three browser exports; the suite needs four.**

- Found during: T2 GREEN.
- Issue: `verifyTotpCandidate` uses `sodium.memcmp` (libsodium WASM); calling it without `await sodium.ready` fails at runtime. The plan didn't expose a ready hook, but the web bundle needs one to pre-warm libsodium at app boot (a synchronous helper called immediately would race the WASM init).
- Fix: added `totpReady()` that awaits the existing `argon2id.ready()`. Exposed via `browser.ts`. Updated `parity.test.ts`'s `BROWSER_ONLY_EXPECTED` snapshot.
- Files modified: `packages/crypto/src/totp.ts`, `packages/crypto/test/parity.test.ts`.
- Commit: `4ea3e73`.

**3. [Rule 1 — Bug] `@simplevault/shared` zod barrel — `fixedB64` declared but never used.**

- Found during: T3 build (TS6133 / `noUnusedLocals`).
- Issue: I drafted both `fixedB64` (exact-length helper) and `boundedB64` (range helper) but only used the latter; the unused symbol triggered the strict-unused gate.
- Fix: dropped `fixedB64` from the file. The login DTO already has its own local copy.
- Files modified: `packages/shared/src/zod/index.ts`.
- Commit: `ca13403`.

**4. [Rule 1 — Bug] Plan-prescribed `AUTH_2FA_TOTP_REPLAY = "E1011"` — code already taken.**

- Found during: T3.
- Issue: Plan 02-T1 (parallel) committed first and claimed E1011..E1014. Plan 03-PLAN.md's draft assumed E1011 for replay — collision.
- Fix: assigned E1015 (`AUTH_2FA_TOTP_REPLAY`) + E1016 (`AUTH_2FA_TOTP_ISSUANCE_INVALID`). Documented in `error-codes.ts` comments. The shared barrel handles the same lookup in either case; clients consuming via discriminator see the same error structure.
- Files modified: `packages/shared/src/error-codes.ts`.
- Commit: bundled into earlier sibling-plan commits (see Deviation 1 below); same code values are present in HEAD.

### Cross-plan parallel-execution artefacts

**1. [Rule 3 — Blocking] T1 RED files bundled into Plan 02-T1's commit (`645c00f`).**

- Found during: post-T1 commit attempt.
- Issue: Plans 02 and 03 were running concurrently. The Plan-02-T1 sibling agent appears to have run a broad `git add` that swept up my staged-and-untracked T1 files (`packages/crypto/src/totp.ts` stub, `packages/crypto/src/browser.ts` re-export, `packages/crypto/test/totp.test.ts`, `packages/crypto/test/parity.test.ts` snapshot update). My subsequent `git commit` reported "no changes added to commit" because they'd already been committed under `645c00f` (`feat(03-02-T1): step-up JWT service ...`).
- Fix: accepted the bundled commit (the contents are correct — the RED test file passes 73 + the surface-presence cases as designed; behaviour cases fail with "not implemented"). Commit message attribution is split across plans 02-T1 + 03-T1, but the FILES are clearly delineated by directory. Future GSD parallel waves should consider per-plan worktrees to avoid this.
- Files affected: `packages/crypto/src/totp.ts` (stub), `packages/crypto/src/browser.ts`, `packages/crypto/test/totp.test.ts`, `packages/crypto/test/parity.test.ts`.
- Commit-of-record for T1 RED: `645c00f` (bundled).

**2. [Rule 3 — Blocking] Audit-events + throttler-config + error-codes edits also bundled into Plan 02-T2 (`d90459f`).**

- Found during: T3 staging.
- Issue: Same parallel-execution artefact as Deviation 1 — my edits to `apps/api/src/common/audit-events.ts` (TwoFaTotp* enum entries), `apps/api/src/common/throttler.config.ts` (twoFaVerifyIp), and `packages/shared/src/error-codes.ts` (E1015 + E1016) were absorbed into Plan 02-T2's commit when the sibling agent ran `git add`.
- Fix: confirmed the edits are present in HEAD (grep verification). My T3 commit (`ca13403`) contains the new files (totp.controller / service / dto + zod schemas) + twofa.module wiring. The cross-plan sweep is documented here for traceability.
- Files affected: `apps/api/src/common/audit-events.ts`, `apps/api/src/common/throttler.config.ts`, `packages/shared/src/error-codes.ts`.
- Commit-of-record for those edits: `d90459f` (bundled into Plan 02-T2).

No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

---

## Hand-offs to later plans

**Plan 03-08 (extend `/auth/login` to branch on 2FA presence):**
- Read presence with: `(SELECT COUNT(*) FROM totp_credentials WHERE user_id = $1) >= 1` (the WebAuthn count is Plan 02's territory). When the OR-sum is ≥ 1, return the `{stepUpToken, twoFa: {webauthnAvailable, totpAvailable}}` 2FA-challenge body shape.
- The step-up token signed by `StepUpJwtService` (Plan 02-T1) is what `/2fa/totp/verify` consumes. No additional plumbing needed in this plan's controller.

**Plan 03-10 (web `/settings/security`):**
- Use `TotpFinishRegisterSchema` from `@simplevault/shared/zod` as the request shape contract.
- The browser ceremony: call `/2fa/totp/begin-register` to get `{issuanceNonce}`; generate a 20-byte secret with `crypto.getRandomValues`; build `provisioningUrl` via `buildOtpauthUrl({issuer:"SimpleVault", account: email, secret})`; render QR; user types first 6-digit code; client computes `currentStep = floor(Date.now()/30000)`, calls `verifyTotpCandidate(secret, typedCode, currentStep, 1)`; if `ok`, wrap the secret with `master_DEK` (AAD = `"sv:user-totp:v1|" || sha256(lower(email))`); POST `/2fa/totp/finish-register` with `{issuanceNonce, wrappedSecret, encryptedSecretAad, name, candidateStep: result.step!}`.

**Plan 03-12 (E2E Cypress `2fa-totp.cy.ts`):**
- Drive begin → finish: synthesise a 20-byte secret in-test, call `computeTotpStep(secret, currentStep)` to get a deterministic 6-digit code. The server has no way to verify the step value's correctness (it doesn't have the secret) — it just runs the CAS. So the test can simulate an attacker feeding a bogus step and observe the replay-401 at the second call.
- **Concurrent-verify race**: two `Promise.all` `/verify` calls with the same `candidateStep`. Exactly one returns 200; the other 401. The atomic UPDATE primitive guarantees this.

---

## Files

**Created:**
- `packages/crypto/src/totp.ts` (~165 lines incl. doc + base32 inline helper)
- `packages/crypto/test/totp.test.ts` (~170 lines, 18 test cases)
- `apps/api/src/twofa/totp/totp.dto.ts` (re-exports from shared)
- `apps/api/src/twofa/totp/totp.service.ts` (~205 lines incl. doc)
- `apps/api/src/twofa/totp/totp.controller.ts` (~225 lines incl. doc)

**Modified:**
- `packages/crypto/src/browser.ts` (`+ export * from "./totp.js"`)
- `packages/crypto/test/parity.test.ts` (snapshot: 4 new browser-only entries)
- `packages/shared/src/zod/index.ts` (4 new schemas + the `boundedB64` helper)
- `packages/shared/src/error-codes.ts` (E1015 + E1016)
- `apps/api/src/twofa/twofa.module.ts` (TotpController + TotpService wiring)
- `apps/api/src/common/audit-events.ts` (4 new audit actions)
- `apps/api/src/common/throttler.config.ts` (twoFaVerifyIp ceiling)

---

## Authentication Gates

None — pure code; no external services touched at execution time.

---

## Verification (final)

- `pnpm --filter @simplevault/crypto build && pnpm --filter @simplevault/crypto test` — 91/91 green.
- `pnpm --filter @simplevault/api build` — green.
- `pnpm --filter @simplevault/web build` — green; the totp browser module compiles into the web bundle without dragging Node `crypto` in.
- `grep -rE "master_(DEK|KEK|kek|dek)" apps/api/src/twofa/totp/` — empty.
- `grep -rnE "computeTotpStep|verifyTotpCandidate|buildOtpauthUrl" apps/api/src/` — only a doc comment in `totp.service.ts` that asserts the invariant; zero imports.
- Parity test enforces the browser-only invariant: `import("../src/node.js")` does NOT contain any of the four totp symbols; `import("../src/browser.js")` does.

---

## Next plans unblocked

- **Plan 03-08** (`/auth/login` branch on 2FA presence): can now test the step-up → TOTP-verify exit path end-to-end.
- **Plan 03-10** (web `/settings/security`): the begin/finish/verify schemas are stable; the browser ceremony helpers are available via `@simplevault/crypto/browser`.
- **Plan 03-12** (E2E Cypress): `2fa-totp.cy.ts` can drive the full flow + the concurrent-verify race scenario.
