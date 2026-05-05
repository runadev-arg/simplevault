# auth-flow-auditor — Phase 03

**Date:** 2026-05-04
**Scope:** Phase 03 — 2FA (WebAuthn + TOTP) + sessions UI / API
**Method:** static read-only audit of API + web + DB schema (no Cypress execution)
**Verdict:** PASS-WITH-CONCERNS

---

## Executive summary

Phase 03 implements the 2FA + sessions surface with substantial care:

- **Two-token discipline (Key Link 5).** Access JWT and step-up JWT share
  the same `JWT_SECRET` but are kept distinct by the `purpose` claim.
  `JwtAuthGuard` decodes (without verification) the inbound token first,
  rejects anything where `payload.purpose !== undefined`
  (`jwt-auth.guard.ts:81-94`), and the dual `Require2FAStepUpGuard`
  rejects anything where `payload.purpose !== "2fa-stepup"`
  (`step-up-jwt.service.ts:81-83`). Confusion is structurally impossible.

- **Truth 8 1FA-precedes-2FA.** `LoginService.login` runs the full
  constant-time Argon2 verifier on every request (with `dummyHash()` on
  miss) BEFORE inspecting `methods.countActive`
  (`login.service.ts:111-130`). The 401 envelope is `{error:{code,message}}`
  byte-equal across "no such user" and "wrong creds" — independent of
  whether the email has 2FA. The 2FA discriminator (`webauthnAvailable`,
  `totpAvailable`) is only emitted to a user who has already passed 1FA.

- **TOTP server-blind (Truth 5 + Key Link 3).** Server-side grep of
  `apps/api/src` for `master_DEK` / `master_kek` / `wrappedMasterDek`
  (case-insensitive) returns ONLY (a) Pino redaction keys in
  `app.module.ts`, (b) DB-row passthrough to the response body in the
  three login-equivalent endpoints (`webauthn-auth.service.ts`,
  `totp.controller.ts:165-227`, `step-up-material.controller.ts`), (c)
  signup persistence. Zero TOTP arithmetic on the server: no import of
  `@simplevault/crypto/browser` or `computeTotpStep` in `apps/api/src`.
  Replay guard is the atomic CAS Drizzle UPDATE
  (`totp.service.ts:176-197` — `lt(lastUsedStep, dto.candidateStep)`
  + `.returning()`); zero rows updated → `AUTH_2FA_TOTP_REPLAY`.

- **WebAuthn counter regression (Truth 4).** `webauthn-auth.service.ts:222`
  rejects when `cred.counter > 0 && newCounter <= cred.counter`,
  `failAudit(userId, "counter_regression")` emits
  `auth.2fa.webauthn.auth.fail`, then throws `WEBAUTHN_VERIFICATION_FAILED`.
  The counter==0 carve-out is documented inline (iCloud-Keychain-synced
  passkeys never increment) — correct trade-off, matches the WebAuthn
  spec recommendation.

- **Atomic challenge consume (Key Link 2).** Both register
  (`webauthn-register.service.ts:168-172`) and auth
  (`webauthn-auth.service.ts:147-151`) use a single
  `DELETE … RETURNING` via `db.execute(sql\`...\`)`. No SELECT-then-DELETE
  TOCTOU window. Expired-by-timestamp double-check after the delete is
  defence-in-depth (the DB row's `expires_at` is also enforced via the
  unique-index TTL).

- **Removal-guard hand-off (Truth 10 + Key Link 7).** `MethodsService`
  exposes `sharedVaultDependencyCheck` as a mutable seam wired to the
  module-level `userHasSharedVaultDependency` stub (currently always
  returns `false` with a `// TODO(phase-07):` comment). When stub flips
  to `true` AND `countAfter === 0`, throws 409 `AUTH_2FA_REMOVAL_BLOCKED`
  with `data:{requires:"shared_vault_2fa"}`. By design — verified.

- **Anti-enumeration on cross-user / unknown-id (Truth 10, 12).**
  `DELETE /2fa/methods/:id` and `DELETE /sessions/:id` both collapse
  cross-user, non-existent, and already-revoked into a uniform 404 with
  `AUTH_INVALID_CREDENTIALS` (`methods.controller.ts:84-90`,
  `sessions.controller.ts:78-83`). No 403 anywhere on these routes.

- **Throttler ordering (FINDING-0021 fold).** `JwtAuthGuard` is
  registered as `APP_GUARD` so it runs BEFORE
  `SimpleVaultThrottlerGuard`. User-keyed buckets (`me-user`,
  `2fa-register-user`, `sessions-list-user`, `sessions-revoke-user`,
  `sessions-revoke-all-user`, `2fa-methods-list-user`,
  `2fa-methods-delete-user`) all key on `req.user.id` post-auth
  (`throttler.config.ts:148-158`).

- **Email-key cap (FINDING-0022 fold).** `login-email` tracker is
  `em:${sha256(email).slice(0,16)}` — fixed 16 hex chars regardless of
  input length (`throttler.config.ts:169-170`). Combined with the
  `varchar(254)` storage cap (FINDING-0017) and the Zod `.max(254)` on
  `LoginSchema.email` / `SignupSchema.email`, the Redis-key flooding
  vector is closed.

- **Session-epoch revoke-all (Truth 14, mandate item 6 part 1).**
  `revokeAllForUser` UPDATEs `user_sessions` THEN calls `bumpEpoch`
  (UPDATE-then-DEL ordered) — verified in `session.service.ts:433-447`
  and `session-epoch.cache.ts:147-159` (DEL-after-UPDATE rationale, plus
  a `bustGen` counter that gates inflight cold-cache SETs against
  concurrent busts; this closes the stale-set race called out in Plan 04
  Key Link 1).

- **WebAuthn library version + explicit RP ID/origin (Key Link 9).**
  `apps/api/package.json` pins `@simplewebauthn/server` and
  `@simplewebauthn/types` to `^11`; web pins `@simplewebauthn/browser`
  to `^11`. Both `verifyRegistrationResponse` and
  `verifyAuthenticationResponse` calls pass `expectedRPID` and
  `expectedOrigin` explicitly. Boot-time guard at
  `webauthn-register.service.ts:63-66` fail-fasts when
  `NODE_ENV === "production"` and either env var is unset.

Three findings surfaced — one of them HIGH (a Truth-12 vs.
implementation drift on single-session-revoke epoch behaviour). The
other two (a defence-in-depth gap on the TOTP `/verify` throttler key,
and a small step-up token TTL window where a concurrent revoke-all
doesn't invalidate the in-flight step-up) are MEDIUM and LOW
respectively.

---

## Per-area findings

### A. Login surface (`/auth/login`, `/auth/refresh`, `/auth/logout`)

PASS. Truth 8 is honoured: 1FA-only failure path is byte-equal across
2FA-enrolled and 2FA-free users (the wrong-creds branch returns
`{error:{code:AUTH_INVALID_CREDENTIALS, message:"Invalid credentials"}}`
without ever consulting `methods.countActive` —
`login.service.ts:116-123`). The 2FA-required success body shape
(`kind:"2fa-required", stepUpToken, twoFa:{...}`) is structurally
distinct from the 1FA-only success body (`accessToken, expiresIn,
wrappedMasterDek, ...`) but both reach the wire ONLY after correct 1FA.

`/auth/refresh` re-stamps the current `session_epoch` from the
Redis-cached read (`refresh.controller.ts:75-85`); the refreshed access
token immediately picks up a `revoke-all` bump.

### B. WebAuthn (`/2fa/webauthn/*`)

PASS. Atomic register-challenge consume; counter regression
correctly enforced with the counter==0 carve-out; `expectedRPID` /
`expectedOrigin` passed explicitly; boot-time fail-fast on missing env
in production. Audit emit on every fail reason
(`challenge_invalid`, `challenge_expired`, `bad_credential_id`,
`credential_not_found`, `verification_threw`, `verification_failed`,
`counter_regression`).

### C. TOTP (`/2fa/totp/*`)

PASS. Atomic CAS replay guard verified
(`UPDATE … WHERE last_used_step < $cs RETURNING`). Issuance nonce uses
`SET … EX 120 NX` then `GETDEL` — single round-trip atomic consume that
matches the WebAuthn DELETE…RETURNING pattern. Server NEVER imports any
`@simplevault/crypto/browser` symbol; grep confirms zero `computeTotpStep`
references in `apps/api/src`.

### D. Step-up token discipline (`step-up-jwt.service.ts`, `step-up.guard.ts`)

PASS. Asymmetric guards form a tight pair: `JwtAuthGuard` rejects
`payload.purpose !== undefined`; `Require2FAStepUpGuard` requires
`payload.purpose === "2fa-stepup"`. Step-up tokens carry no
`sid`/`fam`, only `sub`/`purpose`/`epoch`. TTL clamped to 120s
(env-tunable). The verifier asserts shape THEN purpose THEN epoch type
on every receive (`step-up-jwt.service.ts:76-95`).

### E. `GET /2fa/step-up-material`

PASS. The endpoint is `@Public()` + `@UseGuards(Require2FAStepUpGuard)`
class-wide, so JwtAuthGuard skips and the step-up guard enforces. Body
returns `userArgonSalt` + `argon2Params` + `wrappedMasterDek` +
`totpCredentials[wrappedSecret, encryptedSecretAad]` — all wrapped
under master-DEK / master-KEK keys the server cannot derive. Dropping
material to a step-up-token-bearing client is equivalent to dropping it
to a 1FA-passed client (which the user-facing /auth/login already does
on the no-2FA branch); no new disclosure surface.

### F. Sessions (`/sessions/*`)

MOSTLY PASS — see **F1** below. List endpoint correctly returns the
6-char `ipHashB64Prefix` (not the full hash); the strict-allowlist
output schema (`SessionListResponseSchema.parse`) parses server-side
as a defence-in-depth ORM-leak guard. Cross-user `DELETE /sessions/:id`
collapses to 404. `revokeAll` order is correct (revoke rows FIRST,
bump epoch SECOND) — reversing would race a fresh refresh through.

### G. 2FA methods (`/2fa/methods/*`)

PASS. Strict-allowlist output (no public-key bytes, counters,
transports, wrapped blobs); cross-user / non-existent → uniform 404;
removal guard correctly throws 409 when stub flips. Audit emit on
remove-ok, no audit emit on remove-fail (intentional — see
`sessions.service.ts:42-50` rationale).

### H. Throttler config

PASS for the user-keyed buckets. `login-email` key is hashed + sliced
(FINDING-0022 fix verified). One MEDIUM concern on `2fa-verify-ip`
keying — see **F2** below.

### I. Web `/login`, `/login/2fa`, `/settings/security`, `/settings/sessions`

PASS at static read. `step-up-flow.ts` correctly:
1. unwraps the wrapped TOTP secret with `master_DEK` derived locally,
2. iterates the ±1 drift window comparing against `computeTotpStep`,
3. zeroises the secret + masterKek + masterDek on every exit path
   (`finally { secret.fill(0) }`, `masterKek.fill(0)` etc.),
4. posts `{credentialId, candidateStep}` to `/2fa/totp/verify` — never
   the secret itself.

`applyStepUpSession` rehydrates the in-memory key store identically to
the 1FA-only path's `unlockSecrets` consumer.

Visual UX primacy of the passkey CTA is per the verifier's
human_needed item — not in scope for this static audit.

---

## Mandate item-by-item verdict

| # | Mandate item | Verdict | Evidence |
|---|---|---|---|
| 1 | 2FA enrollment flows do NOT leak whether 2FA is enabled before 1FA succeeds (Truth 8) | PASS | `login.service.ts:111-123` runs constant-time compare with `dummyHash()` BEFORE consulting `methods.countActive`. Failure 401 body is byte-equal across 2FA-enrolled vs 2FA-free users. |
| 2 | TOTP replay guard works under concurrent attack (atomic CAS) | PASS | `totp.service.ts:176-197` Drizzle `update().where(lt(lastUsedStep, candidateStep)).returning()` — single statement; one of two concurrent requests for the same step gets zero rows → 401. |
| 3 | WebAuthn counter regression rejected with `counter_regression` audit reason | PASS | `webauthn-auth.service.ts:222-225` checks `cred.counter > 0 && newCounter <= cred.counter`; `failAudit("counter_regression")` emits `auth.2fa.webauthn.auth.fail`. |
| 4 | Step-up tokens CANNOT be presented to non-`/2fa/*` routes | PASS | `jwt-auth.guard.ts:81-94` (decode-only inspection of `purpose`), `step-up-jwt.service.ts:81-83` (verifier asserts purpose). The two guards are duals. |
| 5 | Removal-while-shared-vault enforcement (test stub flips) | PASS | `methods.service.ts:216-243` — `removeGuarded` reads `before`, computes `countAfter = before - 1`, calls `sharedVaultDependencyCheck`; flipping the seam to return `true` produces 409 `AUTH_2FA_REMOVAL_BLOCKED`. Phase-07 hand-off documented inline. |
| 6 | Session-epoch revokes access tokens within ≤ next-request latency | DRIFT (FAIL for revoke-one, PASS for revoke-all) | `revokeAllForUser` correctly bumps; `revokeOne` deliberately does NOT — see **FINDING-0031** below. Truth 12 says "Bumps the targeted user's session_epoch", code says "intentionally softer". |

---

## Findings

### FINDING-0031 — `DELETE /sessions/:id` does NOT bump `session_epoch`, contradicting Truth 12 — HIGH

**Files:**
- `apps/api/src/auth/sessions/session.service.ts:378-412`
  (`revokeOne` does not call `bumpEpoch`)
- `apps/api/src/sessions/sessions.controller.ts:62-86`
  (controller does not bump either)
- `apps/api/src/sessions/sessions.service.ts:37-62`
  (service-layer wrapper does not bump)
- `.planning/phases/03-2fa-sessions/03-INDEX.md` Truth 12 (specification)

**Evidence.** Truth 12 of `03-INDEX.md` is unambiguous:

> `DELETE /sessions/:id` ... family-revokes the session ... Bumps the
> targeted user's `session_epoch`, cutting all access tokens for that
> user within ≤ next-request latency.

The implementation explicitly opposes this:

```ts
// session.service.ts:378-380
* Does NOT bump the epoch (single-session-revoke is intentionally softer
* than revoke-all — Plan 04 Key Link 3). Only `revokeAllForUser` bumps.
```

`revokeOne` only marks `revoked_at` on the family rows in
`user_sessions`. `JwtAuthGuard` (`jwt-auth.guard.ts`) does NOT consult
`user_sessions.revoked_at` — it validates `epoch` against the cached
`users.session_epoch`. With no epoch bump, the access token issued for
the just-revoked session continues to validate until its
`ACCESS_TOKEN_TTL` expires (default 900s = 15 min).

**Impact.** Concrete attack chain:
1. Attacker steals access token + refresh cookie from victim's device.
2. Victim notices, opens `/settings/sessions`, hits "Sign out" on the
   attacker's session.
3. The refresh cookie is now dead (the family row's `revoked_at` is
   set), but the **access token continues to authenticate any /me /
   /vault.* request for up to 15 minutes**.

The "Sign out a single device" CTA is therefore not what the user
expects: it kills the long-tail refresh chain but leaves the
short-fuse access token alive. Truth 12 was written to close that
window.

The discrepancy is documented in two opposing places (the truth in
the INDEX vs. the code comment in `session.service.ts`); the verifier
report (`03-VERIFICATION.md`) stamps Truth 12 as "VERIFIED" without
catching the contradiction. Either the spec or the code is wrong; the
spec is the auditor-binding artefact.

**Recommendation.** Two equally good fixes — operator decides:
- (a) Wire `bumpEpoch` into `SessionService.revokeOne` (trivial — one
  extra line after the UPDATE-RETURNING). Cost: revoke-one becomes as
  expensive as revoke-all (one extra UPDATE on `users` + Redis DEL),
  AND it kills ALL the user's access tokens, not just the targeted
  session's. The latter is exactly what Truth 12 says ("cutting all
  access tokens for that user").
- (b) Walk back Truth 12 to match the implementation (add "Does NOT
  bump epoch — single-session revoke is intentionally softer; the
  access token's natural TTL is the bound") and surface the
  ≤900s-survives-revoke-one trade-off in the operator runbook +
  `/settings/sessions` UI copy.

**Severity rationale.** HIGH because the auditor mandate's explicit
gate item ("Session-epoch revokes access tokens within ≤ next-request
latency") is satisfied for revoke-all but FAILS for revoke-one — and
the user-facing CTA "Sign out this device" is the very feature the
mandate item is testing. The window is bounded (≤15 min on default
TTL) and the refresh chain IS killed, so this is not Critical (a
patient attacker still loses access). It is HIGH because the spec
contract is broken and a non-technical user would never expect a
"sign out" button to leave them logged in for 15 more minutes.

### FINDING-0032 — `/2fa/totp/verify` rate-limit is IP-keyed, not user-keyed, despite step-up token carrying user-id — MEDIUM

**Files:**
- `apps/api/src/twofa/totp/totp.controller.ts:122-135`
  (`@Throttle({...twoFaVerifyIp})`)
- `apps/api/src/common/throttler.config.ts:69-74` (rate-limit definition)
- `apps/api/src/common/throttler.config.ts:143-173` (`generateKey` — no
  branch for `2fa-verify-ip`)

**Evidence.** TOTP `/verify` is the brute-force gate against a 6-digit
code (1M state space) within a 30-second window (with ±1 drift on the
client side, the effective window is ~90s). Truth 7 + Key Link 4 rely
on the CAS to make replay impossible — but the CAS only catches
**successful guesses being replayed**; it does NOT slow down a brute-
forcer who tries new codes.

The current ceiling is `2fa-verify-ip` = 30 req/min/IP. An attacker
holding a step-up token (which they obtain by completing 1FA on a
legitimate session — i.e. they have password + secret_key already)
can rotate IPs and amortise the brute-force across many sources. The
step-up token's `sub` is the trustworthy user-id — readable by the
throttler's `generateKey` via `req.stepUp?.sub` after
`Require2FAStepUpGuard` runs.

The code comment justifies the IP-keying as "step-up-token-bearer
route (no req.user yet)" — but `req.stepUp.sub` IS available
post-guard, and the throttler runs AFTER `Require2FAStepUpGuard` (it
runs after every guard, NestJS docs).

**Impact.** Realistic: attacker has password+secret_key (e.g. via
keylogger / phishing). They want to bypass 2FA. Per-IP 30/min over
5 minutes from each of 100 IPs = 15,000 codes/window. Per drift
window = 30 valid steps × 90s ≈ 0.5% chance per window if the user
rotates valid codes naturally. Not catastrophic, but the user-keyed
ceiling would tighten this to a pure single-source 30/min — i.e.
1500/30s window = 0.15% chance per window even with infinite IP
budget.

This is defence-in-depth: the user-keyed ceiling was almost certainly
intended (the name `2fa-verify-ip` is explicit about its scope but
the design rationale comment points at user-keying as the future
ideal). Closing the gap is a 5-line change.

**Recommendation.**
1. Rename to `twoFaVerifyUser` (or add a sibling user-keyed ceiling,
   keeping the IP-keyed one as the floor).
2. Extend `generateKey` to branch on `name === "2fa-verify-user"` and
   key by `req.stepUp?.sub` when present, falling back to IP suffix
   when absent.
3. Apply BOTH ceilings on the `/verify` endpoint via `@Throttle({...,
   ...})` so IP and user are both bounded.

**Severity rationale.** MEDIUM because (a) the attacker must have
already compromised 1FA; (b) the IP-keyed ceiling does provide some
brake; (c) the realistic bypass probability is sub-percent per
window. If the realistic threat were a pure "guess 6 digits in 30s
across many IPs", the brute-force probability would still be too low
to count as HIGH.

### FINDING-0033 — Step-up token does not consult `session_epoch` at consume time — LOW

**Files:**
- `apps/api/src/twofa/step-up/step-up.guard.ts` (verifier)
- `apps/api/src/twofa/step-up/step-up-jwt.service.ts:76-95` (claim
  validation — checks `purpose` and types but not `epoch === current`)

**Evidence.** The step-up token carries an `epoch` claim (sampled at
1FA pass) but `Require2FAStepUpGuard.canActivate` only validates
signature + `purpose`. If the user runs `/sessions/revoke-all` in
another tab between 1FA and step-up consume (within the 120s TTL),
the step-up token is honoured — the new session minted by
`/2fa/totp/verify` (or `/2fa/webauthn/finish-auth`) reads the user's
LATEST `session_epoch` from DB (good), so the resulting session is
valid against the new epoch. No real authn bypass.

The concern is conceptual: the step-up token represents "I have
proven 1FA against epoch N"; if epoch advances to N+1, the user has
explicitly invalidated all outstanding state — the step-up token
should arguably die with it.

**Impact.** None practical. The 120s TTL bounds the window. A revoke-
all that happens during the 2FA ceremony will not kill the in-flight
ceremony — but the next-request after the new session lands honours
the new epoch correctly. The user observes "I clicked revoke-all on my
desktop while my phone was mid-step-up — my phone finished the
step-up; subsequent requests on my phone go through the new session,
which is valid."

**Recommendation.** Add an epoch-equality check to
`Require2FAStepUpGuard`:

```ts
const currentEpoch = await this.epochCache.get(claims.sub);
if (claims.epoch !== currentEpoch) throw ...
```

Cost: one Redis GET per step-up-guarded request. Tightens the
revoke-all contract from "kills everything bound to epoch N" to
"kills everything bound to epoch N including in-flight 2FA". Closes
the conceptual gap.

**Severity rationale.** LOW. Window is 120s. Worst case is a
ceremony-completes-after-revoke race that the user might find
surprising; no security impact.

---

## Verdict

**PASS-WITH-CONCERNS.**

Phase 03 implements the 2FA + sessions surface materially correctly:
the load-bearing invariants (TOTP server-blind, atomic CAS replay
guard, WebAuthn counter regression, step-up token isolation, removal-
guard hand-off, Truth 8 1FA-precedes-2FA, throttler ordering, email-
key cap) all PASS. The HIGH **FINDING-0031** is a spec-vs-code drift
that falls inside the mandate's explicit gate item ("Session-epoch
revokes access tokens within ≤ next-request latency") and therefore
blocks Phase 03 from flipping to PASS until either (a) the
implementation bumps epoch on revoke-one, or (b) Truth 12 is rewritten
to match the implementation and the user-facing copy is updated.

**Action required for Phase 03 gate to flip to PASS:**
- Resolve FINDING-0031 (HIGH): align `revokeOne` with Truth 12, OR
  amend Truth 12 + add operator-runbook + UI-copy callout.

**Non-blocking cleanups (recommended in this phase or Phase 13):**
- FINDING-0032 (MEDIUM): user-key the `/2fa/totp/verify` throttler.
- FINDING-0033 (LOW): epoch-check the step-up guard.

---

## Confidence + caveats

- Cypress specs were NOT executed. The four 2FA / sessions specs are
  present and structurally reference the CDP virtual authenticator,
  but a green CI run is the Plan 12 T4 operator checkpoint.
- Visual UX primacy (passkey CTA styling vs TOTP) is also human-
  needed — copy strings present but ordering/styling needs eyes.
- No live runtime probe of the throttler buckets — static read of
  `generateKey` only.
- The TOTP brute-force calculation in FINDING-0032 assumes the
  attacker has unlimited IP rotation. In SimpleVault's ≤50-user
  threat model, this is plausible (cloud-IP spray) but not
  catastrophic.

---

## Re-run 2026-05-04 — FINDING-0031 closure verification

**Scope:** narrow re-verification of FINDING-0031 only.

**File spot-checked:** `apps/api/src/auth/sessions/session.service.ts`
lines 372-421 (`revokeOne`). Compared against `revokeAllForUser`
lines 423-456 for ordering parity.

### Code-line evidence

`revokeOne` now does, in order:

1. L397-403 — SELECT-then-guard: if no row owned by `userId`,
   return `null`. No epoch bump on cross-user / not-found probe.
2. L405-410 — UPDATE family rows, RETURNING id.
3. L411-418 — if `revokedCount === 0` (race: revoked between
   SELECT and UPDATE), return `null`. **Still no bump** — correct,
   nothing was actually killed by this call.
4. L419 — `await this.bumpEpoch(userId)` AFTER successful UPDATE.
5. L420 — return `{familyId, revokedCount}`.

Doc-comment L378-387 explicitly calls out the ordering as
load-bearing and references `revokeAllForUser`'s matching note
(L430-437). Reasoning given (per-user grain because access tokens
carry only `epoch`, not `sid`/`fam`) is correct — matches Plan 04
Key Link 3 logic and closes the AT-5 leaf-A residual.

### Truth 12 satisfaction

03-INDEX.md L22 Truth 12: *"Bumps the targeted user's
`session_epoch`, cutting all access tokens for that user within ≤
next-request latency."* → **Now satisfied** (L419 invokes the same
`bumpEpoch` primitive from Plan 04, which is itself UPDATE-then-DEL
ordered, L264-267).

### Anti-enumeration regression check

The `null`-return path (cross-user, not-found, already-revoked) is
preserved on L403 and L417 — both BEFORE the L419 bump. Cross-user
probes therefore do NOT bump the attacker's epoch (would have been a
self-DOS vector + a side-channel oracle: an attacker bumping their
OWN epoch via probes is harmless, but a victim observing
their-own-tokens-still-valid after a probe gives no signal anyway —
still, the guard is correct on its own merits).

### New concerns surfaced

1. **Stale doc-comment on `bumpEpoch` itself (L252-258)** still
   reads: *"Call this from `/sessions/revoke-all` (Plan 05) —
   single-session revoke (`DELETE /sessions/:id`) does NOT call
   this (per Plan 04 Key Link 3 — bumping per single-session-revoke
   would invalidate other valid sessions' access tokens for the
   same user)."* This is now contradicted by `revokeOne`'s L419.
   Documentation drift, not a security bug, but **MUST be fixed**
   to avoid future devs "restoring" the old behaviour. Filed as
   **FINDING-0034 (INFO):** stale doc-comment on
   `SessionService.bumpEpoch`.

2. **No race window concern.** The order (UPDATE refresh rows →
   bumpEpoch) is the same load-bearing order as `revokeAllForUser`
   and is safe. Reverse-order scenario (bump first → window where
   old refresh cookie can mint new access under new epoch) does not
   apply here.

3. **Test gap (INFO, non-blocking).** No unit/integration spec was
   found exercising `DELETE /sessions/:id` followed by an access-
   token rejection assertion. Closest specs in
   `apps/api/test/`: `jwt-epoch.spec.ts` (covers epoch reject path
   generally), `2fa-removal.spec.ts`. Recommend a Phase-13 add:
   spec that (a) logs in two sessions for one user, (b) DELETEs
   session A by id, (c) asserts session A's access token → 401
   `AUTH_SESSION_REVOKED`, (d) asserts session B's access token
   also rejected once (bump is per-user, by design — UX cost
   accepted in Truth 12). Not blocking — Cypress
   `sessions.cy.ts` (Plan 12 T1) likely covers (a)+(c) at the
   browser level; api-level reproducibility would still help.

### Verdict

- **FINDING-0031: VERIFIED-CLOSED.**
- New **FINDING-0034 (INFO):** stale `bumpEpoch` JSDoc — fix in
  Phase 03 closeout (one-line doc edit).
- **Updated Phase-03 top-line verdict:** **PASS** (was
  PASS-WITH-CONCERNS). Remaining open items are FINDING-0032
  (MEDIUM, deferrable to Phase 13) and FINDING-0033 (LOW,
  deferrable). Neither blocks Phase 03 sign-off; both are tracked.
