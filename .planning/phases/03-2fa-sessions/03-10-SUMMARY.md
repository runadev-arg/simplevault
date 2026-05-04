---
phase: 03-2fa-sessions
plan: 10
subsystem: web-2fa
tags: [web, 2fa, webauthn, totp, step-up, ui, settings, login-2fa, truth-5, truth-6, truth-7, truth-9, truth-10, truth-16, key-link-3, key-link-12]
requires:
  - 03-02 (WebAuthn API: begin/finish-register, begin/finish-auth, step-up JWT)
  - 03-03 (TOTP API: begin/finish-register, /verify, browser-only RFC 6238)
  - 03-06 (2FA methods API: GET /2fa/methods, DELETE /2fa/methods/:id)
  - 03-08 (login branches on 2FA presence + emits step-up token)
provides:
  - "Web /settings/security 2FA enrolment UI (passkey + TOTP)"
  - "Web /login/2fa step-up consumer (passkey + TOTP)"
  - "NEW API: GET /2fa/step-up-material (step-up guarded) — folds wrapped TOTP secrets + unwrap material into one roundtrip"
  - "apps/web/src/lib/api/twofa-client.ts typed wrappers"
  - "apps/web/src/lib/auth/step-up-flow.ts (completeWithPasskey, findTotpMatch, completeWithTotp, applyStepUpSession)"
  - "apps/web/src/lib/crypto/totp-wrap.ts (wrap/unwrap helpers, AAD `sv:user-totp:v1|`)"
affects:
  - 03-12 (Cypress E2E: 2fa-webauthn.cy.ts + 2fa-totp.cy.ts must exercise enrol + sign-in across both ceremonies; UX-copy regression spec asserts the phishing-warning string is rendered above the TOTP enrol button)
  - Phase 07 (shared vaults): the AUTH_2FA_REMOVAL_BLOCKED 409 path is wired in the UI; Phase 07 flips the server stub from `() => false` to the real shared-vault dependency check.
tech-stack:
  added:
    - "@simplewebauthn/browser@^11 (web — passkey ceremony driver)"
    - "qrcode + @types/qrcode (web — TOTP setup QR rendering)"
  patterns:
    - "Reuses the shared `request` helper from auth-client.ts (Plan 11 export). Same Zod-validated typed wrappers as auth-client / sessions-client."
    - "TOTP wrap follows the existing AAD pattern (label || SHA256(lower(email)) → encodeAad(argon2Params, ctx)) — same scheme as wrappedMasterDek / wrappedUserSigningSk. AAD bytes round-trip through the server (defence in depth: any AAD substitution surfaces as a tag mismatch on decrypt)."
    - "Soft `router.push('/login/2fa')` (NOT window.location.assign) preserves the JS realm so the keyStore singleton survives the hand-off. Plan 08 used a hard nav and wiped keyStore — that worked for the inter-wave window because no /login/2fa existed; Plan 10 replaces it with the soft-nav handoff."
key-files:
  created:
    - apps/api/src/twofa/step-up/step-up-material.controller.ts
    - apps/web/src/app/(authed)/settings/security/page.tsx
    - apps/web/src/app/(authed)/settings/security/method-list.tsx
    - apps/web/src/app/(authed)/settings/security/enroll-passkey-button.tsx
    - apps/web/src/app/(authed)/settings/security/enroll-totp-flow.tsx
    - apps/web/src/app/login/2fa/page.tsx
    - apps/web/src/lib/api/twofa-client.ts
    - apps/web/src/lib/auth/step-up-flow.ts
    - apps/web/src/lib/crypto/totp-wrap.ts
  modified:
    - apps/api/src/twofa/twofa.module.ts (register StepUpMaterialController)
    - apps/web/package.json + pnpm-lock.yaml (@simplewebauthn/browser, qrcode, @types/qrcode)
    - apps/web/src/lib/crypto/aad-labels.ts (AAD_LABEL_TOTP)
    - apps/web/src/app/login/page.tsx (soft router.push for 2FA branch + keyStore handoff)
duration: ~2.0h
completed: 2026-05-04 (T1–T3); checkpoint T4 owed to operator (visual UX confirmation)
---

# Phase 03 Plan 10: Web 2FA enrolment + /login/2fa step-up consumer

`/settings/security` ships the user-facing 2FA management surface — list
existing methods, add a passkey (PRIMARY CTA, phishing-resistant), add an
authenticator app (SECONDARY, with the THREAT-MODEL §17-mandated
phishing-warning copy). `/login/2fa` consumes the step-up token from
sessionStorage and walks the user through whichever ceremony their
account has enrolled (passkey first, TOTP fallback). The TOTP step-up
path required ONE new API endpoint (`GET /2fa/step-up-material`) and a
soft-nav handoff that preserves the user's typed password + secret_key
in keyStore — both deviations from the plan's text, documented below.

**Status:** T1–T3 COMPLETE; **T4 (operator UX checkpoint) PENDING.**
**Date:** 2026-05-04
**Commits:** `e2e8905` (T1), `df46767` (T2), `e18821d` (T3)
**Tasks:** 3/4 (T4 = operator UX verification)

---

## What landed

### Task 1 — `feat(03-10-T1): /settings/security skeleton + GET /2fa/methods + UX copy` (`e2e8905`)

**`apps/web/src/lib/api/twofa-client.ts` (new)** — typed wrappers for
every Phase-03 2FA endpoint. Reuses the shared `request` helper from
`auth-client.ts` (exported in Plan 11's T1 commit) so fetch + Zod
validation + uniform error envelopes stay single-source.

  - `getMethods` / `removeMethod` — auth-token guarded (Truth 9, 10).
  - `beginWebauthnRegister` / `finishWebauthnRegister` — auth-token (T2).
  - `beginWebauthnAuth` / `finishWebauthnAuth` — step-up token (T3).
  - `beginTotpRegister` / `finishTotpRegister` — auth-token (T3).
  - `verifyTotp` — step-up token (T3).
  - `getStepUpMaterial` — step-up token (T3 — see "Deviations" below).

**`apps/web/src/app/(authed)/settings/security/page.tsx`** — the route
entry. Renders `<MethodList />`, `<EnrollPasskeyButton />` (T2), and
`<EnrollTotpFlow />` (T3). The two enrol sections sit in panels with
explicit visual weight per INDEX Key Link 12:
  - **Passkey** in an emerald-bordered panel with a "Recommended —
    phishing-resistant" badge (PRIMARY CTA).
  - **Authenticator app** in a zinc panel with an amber-bordered
    warning panel ABOVE the enrol button containing the verbatim copy:

      > "Authenticator-app codes can be entered into a phishing site.
      >  Use a passkey when possible — passkeys cryptographically
      >  refuse to log in to a fake site."

    The auth-flow-auditor at the gate review will check this copy +
    ordering; T4 surfaces it for visual confirmation by the operator.

**`apps/web/src/app/(authed)/settings/security/method-list.tsx`** —
fetches `GET /2fa/methods` on mount. Per-row badge: emerald PASSKEY for
webauthn entries, amber AUTHENTICATOR APP for totp. Remove button hits
`DELETE /2fa/methods/:id`; surfaces the Phase-07-aware
`AUTH_2FA_REMOVAL_BLOCKED` 409 with forward-looking shared-vault copy
(the Phase-03 server stub never returns 409, but the UI is wired so
Phase 07 only has to flip the server flag).

### Task 2 — `feat(03-10-T2): passkey enrolment via @simplewebauthn/browser` (`df46767`)

**`apps/web/src/app/(authed)/settings/security/enroll-passkey-button.tsx` (new)**
— wires the "Add passkey" button via `@simplewebauthn/browser@^11`
(pinned to the same major as the server-side `@simplewebauthn/server`).

  1. POST `/2fa/webauthn/begin-register` → JSON ceremony options.
  2. `startRegistration({ optionsJSON })` drives
     `navigator.credentials.create()` — browser prompts for biometric/PIN.
  3. POST `/2fa/webauthn/finish-register` with the attestation + chosen
     name. On success the parent `<MethodList>` re-fetches.

`NotAllowedError` (user cancel / no authenticator available) surfaces
as a graceful "Cancelled" status — NOT a red error. Other failures
bubble up with the library's message for diagnostic visibility.

Bundle delta: `/settings/security` First-Load JS goes from 127 kB to
130 kB (+3 kB after gzip — passkey enrolment + the
@simplewebauthn/browser library).

### Task 3 — `feat(03-10-T3): TOTP enrolment + /login/2fa step-up consumer + step-up material API` (`e18821d`)

The largest commit in Plan 10. Three sub-deliverables:

#### 3a) Server: `GET /2fa/step-up-material`

**`apps/api/src/twofa/step-up/step-up-material.controller.ts` (new)** —
Step-up-token-guarded endpoint that returns ALL the material the web
client needs to complete a TOTP step-up:

```ts
{
  userArgonSalt: string,            // base64, 16 B
  argon2Params: { memoryKiB, iterations, parallelism: 1 },
  wrappedMasterDek: string,         // base64 of nonce || ciphertext
  totpCredentials: [
    {
      id: string (uuid),
      name: string,
      wrappedSecret: string,        // base64 of nonce || ciphertext
      encryptedSecretAad: string,   // base64 of the AAD bytes used at wrap time
    },
    ...
  ],
}
```

The `userArgonSalt + argon2Params + wrappedMasterDek` triple lets the
client derive `master_DEK` locally from the password + secret_key
preserved in the keyStore across the soft `/login` → `/login/2fa`
navigation. The `totpCredentials[]` carry the wrapped secrets the
client decrypts with `master_DEK` to compute candidate steps.

Throttled at the existing `2fa-verify-ip` ceiling (30/min IP-keyed) —
the endpoint sits on the step-up auth path and the same anti-abuse
envelope applies.

Wired into `TwoFaModule.controllers`. Step-up auth happens via
`@UseGuards(Require2FAStepUpGuard)` plus a class-level `@Public()` to
opt out of the global JwtAuthGuard (which would reject the
`purpose:"2fa-stepup"` token by Plan 02 / Key Link 5).

#### 3b) Web: TOTP enrolment in `/settings/security`

**`apps/web/src/lib/crypto/aad-labels.ts`** — adds
`AAD_LABEL_TOTP = "sv:user-totp:v1|"` (matches the schema's bound +
the comment Phase 03-01 left for us).

**`apps/web/src/lib/crypto/totp-wrap.ts` (new)** — `wrapTotpSecret` /
`unwrapTotpSecret` helpers using the same scheme as the existing
master / sign-sk / kx-sk wraps:

```
AAD = encodeAad(argon2Params, AAD_LABEL_TOTP || SHA256(lower(email)))
wrappedSecret = base64(nonce(24) || XChaCha20-Poly1305(secret, master_DEK, AAD))
```

`computeTotpAad` is exported so the AAD can be recomputed at decrypt
time and compared against the bytes the server returned (defence in
depth — see Plan 10 SUMMARY §"AAD round-trip" below).

**`apps/web/src/app/(authed)/settings/security/enroll-totp-flow.tsx`
(new)** — full enrolment wizard:

  1. POST `/2fa/totp/begin-register` → `{ issuanceNonce }` (TTL 120s).
  2. `sodium.randombytes_buf(20)` → 20-byte secret (RFC 6238 norm).
  3. `buildOtpauthUrl({issuer, account: email, secret})` → otpauth URL.
  4. `QRCode.toDataURL(url)` → display QR + collapsible URL fallback.
  5. User enters code; `verifyTotpCandidate(secret, code, currentStep, drift=1)`.
  6. On match: `wrapTotpSecret(secret, master_DEK, email, argon2Params)`
     → POST `/2fa/totp/finish-register` with the wrapped blob.
  7. Wipe local secret + transition to "done" + refresh `<MethodList>`.

`master_DEK` comes from `keyStore.getBytes("master_dek")` — set by the
1FA login flow. If missing (e.g. hard-refresh post-login), the UI
surfaces a clear "log out and back in" hint — adding TOTP requires
the unwrapped DEK to be in memory.

The `name` field defaults to "Authenticator" but the user can override.
Best-effort secret zeroing on every transition / cancel / success.

#### 3c) Web: `/login/2fa` step-up consumer

**`apps/web/src/lib/auth/step-up-flow.ts` (new)** — three primitives:

  - `completeWithPasskey(stepUpToken)` — runs the WebAuthn assertion
    ceremony via `@simplewebauthn/browser` and POSTs `/2fa/webauthn/finish-auth`.
    Returns the same shape as a 1FA-only login response.
  - `loadStepUpMaterial(stepUpToken)` — thin wrapper around the new
    `GET /2fa/step-up-material` endpoint.
  - `findTotpMatch(material, email, password, secretKey, code)` —
    re-derives `master_KEK` locally from the password + secret_key +
    the unwrap material; iterates over the user's TOTP credentials
    and the ±1-step drift window to identify which credential the
    typed code matches. Returns `{credentialId, candidateStep,
    masterDek}`.
  - `completeWithTotp(stepUpToken, credentialId, candidateStep)` —
    POST `/2fa/totp/verify`.
  - `applyStepUpSession(result, email, password, secretKey)` — runs
    the same `unlockSecrets` path as 1FA login to populate keyStore
    with master_KEK / master_DEK / signing_sk / kx_sk.

**`apps/web/src/app/login/2fa/page.tsx` (new)** — the consumer route:

  1. On mount, read `{token, twoFa}` from `sessionStorage`. Missing
     handoff → redirect to `/login`.
  2. Lazy-fetch step-up material when `twoFa.totpAvailable === true`.
     WebAuthn-only accounts skip this fetch.
  3. Render Use-passkey button (PRIMARY when available) and Enter-code
     form (SECONDARY when TOTP enrolled).
  4. On either ceremony complete: `applyStepUpSession()` populates the
     keyStore + accessTokenStore, hard-redirect to `/me`.
  5. On expired step-up / missing keyStore handoff / cancel: wipe
     everything + bounce back to `/login`.

**`apps/web/src/app/login/page.tsx`** — switched the 2FA-required
branch from `window.location.assign("/login/2fa")` to a soft
`router.push("/login/2fa")` so the JS realm survives the hand-off
(keyStore singleton persists). Stashes `step_up_email +
step_up_password + step_up_secret_key` in keyStore for `/login/2fa` to
consume. The 1FA-only branch is unchanged byte-for-byte.

### Task 4 — `checkpoint(03-10-T4): operator UX verification` — **PENDING**

Operator must open `/settings/security` in a logged-in dev session and
visually confirm:

  1. The "Add passkey" panel sits ABOVE the "Add authenticator app"
     panel.
  2. Visual weight: emerald-bordered panel + "Recommended —
     phishing-resistant" badge on passkey vs zinc + amber-warning on
     TOTP.
  3. Amber warning panel sits ABOVE the "Set up authenticator app"
     button — users read it BEFORE clicking.
  4. Exact copy block "Authenticator-app codes can be entered into a
     phishing site. Use a passkey when possible — passkeys
     cryptographically refuse to log in to a fake site." appears in
     the rendered DOM.
  5. PASSKEY (emerald) and AUTHENTICATOR APP (amber) badges in the
     existing-methods list are visually distinct.

**Source-side verification (what Claude can do):**
  - `grep -n "Add passkey\|Add authenticator\|Recommended\|cryptographically refuse\|phishing site" apps/web/src/app/(authed)/settings/security/page.tsx`
    → returns: line 52 (Add passkey), 55 (Recommended — phishing-resistant), 68
      (Add authenticator app), 74-75 (the verbatim phishing-warning copy).
  - Source-order: passkey panel at line 50 < TOTP panel at line 67 < amber
    warning panel at line 73 < (Plan 10 T3) `<EnrollTotpFlow />` at line 82.
    Ordering is correct in source.

Operator: open the dev server, log in, navigate to `/settings/security`,
take a screenshot, save to
`.planning/phases/03-2fa-sessions/03-10-uxcheck.png` (or describe
verification inline below this section). Mark T4 ✅ in STATE.md.

---

## Truths verified (T1–T3)

| # | Truth (from `03-INDEX.md`) | Status |
|---|---|---|
| T5 | TOTP secret 20 random bytes generated client-side; QR + provisioning URL displayed; finish-register accepts wrapped blob | OK — `enroll-totp-flow.tsx` + `wrapTotpSecret` + new endpoint folds it together |
| T6 | finish-register on the wire is `{issuanceNonce, wrappedSecret, encryptedSecretAad, name, candidateStep}` | OK — `TotpFinishRegisterRequest` + `finishTotpRegister` |
| T7 | Step-up TOTP verify: client decrypts, computes locally, posts `{credentialId, candidateStep}` → server CAS replay-guard → mints session | OK — `findTotpMatch` + `completeWithTotp`; uses `GET /2fa/step-up-material` to obtain wrapped material under step-up auth |
| T9 | `GET /2fa/methods` lists active methods; web shows kind badges + name + createdAt + lastUsedAt | OK — `<MethodList />` |
| T10 | `DELETE /2fa/methods/:id`; on 409 AUTH_2FA_REMOVAL_BLOCKED show forward-looking shared-vault copy | OK — `<MethodRow>` checks `e.code === "E1018"` |
| T16 | "/settings/security lists 2FA methods, has 'Add passkey' (PRIMARY phishing-resistant copy) + 'Add authenticator app' (SECONDARY) with phishing-warning copy" | **CODE-LEVEL OK** — visual confirmation owed to operator (T4) |

---

## Decisions made

1. **One new endpoint instead of two.** The plan called out `GET
   /2fa/totp/credentials` returning only the wrapped secrets — but
   completing the TOTP ceremony client-side ALSO needs `userArgonSalt +
   argon2Params + wrappedMasterDek` (the 2FA-required login response
   deliberately omits these per Plan 08 anti-enumeration). Rather than
   land two endpoints, I folded both into one: `GET
   /2fa/step-up-material`. Saves a roundtrip and keeps the new surface
   to one route. Step-up-token guarded; throttled at the existing
   `2fa-verify-ip` ceiling.

2. **Soft `router.push` for the 2FA-required handoff** (was
   `window.location.assign` per Plan 08). Hard nav tears down the JS
   realm including the keyStore singleton; soft nav preserves it so
   the user's password + secret_key + email survive across `/login` →
   `/login/2fa`. Required because deriving `master_DEK` at /login/2fa
   needs the user's typed credentials, and re-prompting for them
   would be terrible UX.

3. **Stash password / secret_key in keyStore (NOT sessionStorage).**
   keyStore is in-memory only; sessionStorage is an attack surface for
   XSS. Even though the CSP nonce + same-origin posture make XSS hard,
   keeping the most-sensitive material in JS heap minimises the
   exposure window. The step-up token (less sensitive — server
   enforces 120s TTL + step-up-only routes) stays in sessionStorage
   for cross-navigation handoff per Plan 08.

4. **`Intl.RelativeTimeFormat` over `date-fns`** — same call as Plan 11.

5. **`@simplewebauthn/browser@^11` pin** — matches the server's
   `@simplewebauthn/server@^11` pin (Plan 02). Mismatched majors
   silently break ceremony JSON shapes. The pin should track
   server upgrades.

6. **AAD round-trip from server.** The `encryptedSecretAad` bytes the
   server stores are recomputable client-side (label + emailHash +
   argon2Params), but storing + round-tripping them adds defence in
   depth: any active attacker who substitutes the AAD on the wire
   surfaces as a tag mismatch on `unwrapTotpSecret`. The client could
   ALSO recompute and assert byte-equality — deferred to a future
   hardening pass; the tag-mismatch already covers the "bad AAD"
   case.

7. **`master_DEK` zeroed after `findTotpMatch`** — the helper returns
   the derived `masterDek` so the caller can pass it on if needed,
   but in the consumer (`/login/2fa`) we wipe it immediately after
   the verify call lands; `applyStepUpSession` will re-derive it
   from the verify response's wrapped material via `unlockSecrets`.
   Belt-and-braces: a single `master_DEK` instance never lives
   longer than the ceremony.

8. **No `auth-context.tsx` extension.** The plan listed
   "auth-context.tsx (extend with stepUpToken state)" but Plan 08's
   sessionStorage-based handoff already works end-to-end and the
   `/login/2fa` page reads it directly. Adding a stepUp field to
   AuthContext would have churned the (authed) layout for no
   behavioural gain. Reconsider in Phase 13 if the page tree grows
   to need shared step-up state.

---

## AAD round-trip pattern (load-bearing — read before changing)

The TOTP wrap follows the same pattern as `wrappedMasterDek` /
`wrappedUserSigningSk` etc. but with one extra wrinkle: the server
stores both the wrapped blob AND the AAD bytes used at wrap time
(`totp_credentials.encrypted_secret_aad bytea`). The plan calls these
"the AAD bytes used at wrap time"; here's the security reasoning:

  - At wrap time: client computes `aad = encodeAad(params,
    AAD_LABEL_TOTP || SHA256(lower(email)))`, encrypts the secret
    with `(masterDek, aad)`, and posts BOTH `wrappedSecret` and `aad`
    base64-encoded.
  - At decrypt time: client receives `wrappedSecret` and the
    server-stored `aad`, calls `decrypt(blob, masterDek, aad)`. Tag
    mismatch → wrong key OR wrong AAD OR mutated blob — caller can't
    distinguish (which is fine).
  - DEFENCE IN DEPTH: the client COULD recompute `aad` locally and
    assert byte-equality with the server-supplied bytes, refusing to
    decrypt if they differ. Not done in this commit — deferred to a
    future hardening pass. The tag mismatch already prevents
    decryption in the AAD-substitution case.
  - The server NEVER decrypts; it only round-trips opaque bytes.
    `apps/api/src/twofa/totp/totp.service.ts` carries a comment
    asserting "Server NEVER sees plaintext" + the server-side grep
    is clean for `master_DEK` / `computeTotpStep` / `verifyTotpCandidate`.

---

## Server-side grep (Plan 03 Key Link 3)

```
$ grep -rE "master_dek|master_kek|masterDek|masterKek|computeTotpStep|verifyTotpCandidate" apps/api/src/twofa/
apps/api/src/twofa/webauthn/webauthn-auth.service.ts: ... wrapped_master_dek (opaque bytes round-trip)
apps/api/src/twofa/totp/totp.service.ts: * ... `computeTotpStep` / `verifyTotpCandidate` / `buildOtpauthUrl`).  (comment, not import)
```

Zero references to `master_DEK` / `master_KEK` plaintext. Zero
imports of `computeTotpStep` / `verifyTotpCandidate` from the
TOTP server module. The two webauthn-auth.service hits are
opaque bytea round-trip in the post-finish-auth response — same
shape as a 1FA login response.

---

## Deviations from plan

### Auto-fixed issues

**1. [Rule 3 — Architectural] Login response doesn't carry unwrap material.**

- **Found during:** T3 design.
- **Issue:** The 2FA-required login response (Plan 08) returns ONLY
  `{stepUpToken, twoFa}`. To complete TOTP step-up client-side the
  client needs to derive `master_DEK`, which requires
  `userArgonSalt + argon2Params + wrappedMasterDek` — none of which
  are in the 2FA-required response. The plan implied "completeWithTotp
  reads from keyStore" without addressing where the unwrap material
  comes from.
- **Fix:** Add `GET /2fa/step-up-material` (step-up-token-guarded)
  returning the unwrap material AND the wrapped TOTP secrets in one
  payload. Documented in 03-10-PLAN.md's text as "one new endpoint";
  the unbundling decision keeps the new surface to a single route
  rather than two (was tempted to do `GET /2fa/totp/credentials` +
  `GET /2fa/unlock-material`).
- **Files modified:** `apps/api/src/twofa/step-up/step-up-material.controller.ts`,
  `apps/api/src/twofa/twofa.module.ts`,
  `apps/web/src/lib/api/twofa-client.ts`,
  `apps/web/src/lib/auth/step-up-flow.ts`.
- **Commit:** rolled into T3 (`e18821d`).

**2. [Rule 3 — Architectural] /login → /login/2fa hard nav tears down keyStore.**

- **Found during:** T3 design.
- **Issue:** Plan 08 used `window.location.assign("/login/2fa")` and
  wiped the keyStore. That worked for the inter-wave window because
  /login/2fa didn't exist. But the hard nav tears down the JS realm,
  so any in-memory secret (password, secret_key) the user just typed
  is GONE before /login/2fa loads.
- **Fix:** Switch to soft `router.push("/login/2fa")` (preserves the
  JS realm so the keyStore singleton survives). Stash password +
  secret_key + email in keyStore via the dedicated keys
  `step_up_email` / `step_up_password` / `step_up_secret_key`. The
  step-up token + flags continue to use sessionStorage per Plan 08.
- **Files modified:** `apps/web/src/app/login/page.tsx`.
- **Commit:** rolled into T3 (`e18821d`).

**3. [Rule 1 — Bug] TS narrowing on `accessToken` after `canSubmit` guard.**

- **Found during:** T2 build verification.
- **Issue:** The Next.js build's lint reported `Unnecessary conditional, the
  types have no overlap` on `if (!canSubmit || accessToken === null)` because
  `canSubmit` already guarantees `accessToken !== null` via its computation.
- **Fix:** Drop the redundant null check; rely on `canSubmit`'s narrowing
  via a `const at = accessToken;` rebind that TS infers as non-null.
- **Files modified:** `apps/web/src/app/(authed)/settings/security/enroll-passkey-button.tsx`.
- **Commit:** folded into T2 (`df46767`).

### No Rule 4 deviations beyond the architectural ones above.

### Pre-existing lint issues (unchanged from parent commit)

The api lint reports the same 8 pre-existing errors that were present
at parent commit `b0e8bc7`. None introduced by this plan.

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm typecheck` (apps/api + apps/web) | GREEN |
| `pnpm test` (apps/api, vitest) | GREEN — 32/32 (no regressions) |
| `pnpm build` (apps/api, nest) | GREEN |
| `pnpm build` (apps/web, next) | GREEN — `/settings/security` 548 kB First-Load (libsodium dominates), `/login/2fa` 538 kB |
| Server-side grep (master_DEK / TOTP plaintext in apps/api/src/twofa/) | CLEAN — zero references except opaque bytea round-trip |
| UX visual confirmation (T4) | **PENDING — operator screenshot owed** |

---

## Bundle size deltas

| Route | Before | After | Delta |
|---|---|---|---|
| `/settings/security` | (didn't exist) | 548 kB | +548 kB |
| `/settings/sessions` (Plan 11) | (didn't exist) | 127 kB | +127 kB |
| `/login/2fa` | (didn't exist) | 538 kB | +538 kB |
| `/login` | 534 kB | 534 kB | unchanged |
| `/me` | 119 kB | 118 kB | -1 kB (chunk reshuffle) |

The +400-ish kB on `/settings/security` and `/login/2fa` is dominated
by `libsodium-wrappers-sumo` (already loaded by /login + /signup —
Webpack reuses the chunk; the per-route number is the chunk-aware
First-Load JS as Next reports it). Acceptable for a self-hosted
≤50-user app where the user has already loaded libsodium during
sign-in.

---

## Hand-offs

**Plan 03-12 (E2E Cypress):**
  - `2fa-webauthn.cy.ts`: enrol via /settings/security (CDP virtual
    authenticator); log out; log in; assert /login/2fa shows "Use
    passkey" CTA; complete ceremony; assert /me lands.
  - `2fa-totp.cy.ts`: enrol via /settings/security (deterministic
    test-vector secret seeded into the form); log out; log in;
    assert /login/2fa shows "Enter code" form; type the code derived
    from the test vector; assert /me lands.
  - UX-copy regression: `cy.contains("cryptographically refuse to log
    in to a fake site")` to assert the THREAT-MODEL §17 copy is
    rendered.
  - Removal-guard: stub the server flag to `() => true` (Plan 06's
    integration mechanism) → assert the "shared vault" 409 message
    surfaces in the UI.

**Phase 07 (shared vaults):** the AUTH_2FA_REMOVAL_BLOCKED 409 path
is already wired in `<MethodRow>`. Phase 07 only has to flip the
server stub from `() => false` to the real shared-vault dependency
check.

**Operator (T4):** open `/settings/security` in a logged-in dev
session, take the screenshot, store it under
`.planning/phases/03-2fa-sessions/03-10-uxcheck.png`. Then mark T4
complete in STATE.md.

---

## Files

**Created (new):**
- `apps/api/src/twofa/step-up/step-up-material.controller.ts`
- `apps/web/src/app/(authed)/settings/security/page.tsx`
- `apps/web/src/app/(authed)/settings/security/method-list.tsx`
- `apps/web/src/app/(authed)/settings/security/enroll-passkey-button.tsx`
- `apps/web/src/app/(authed)/settings/security/enroll-totp-flow.tsx`
- `apps/web/src/app/login/2fa/page.tsx`
- `apps/web/src/lib/api/twofa-client.ts`
- `apps/web/src/lib/auth/step-up-flow.ts`
- `apps/web/src/lib/crypto/totp-wrap.ts`

**Modified:**
- `apps/api/src/twofa/twofa.module.ts` (register StepUpMaterialController)
- `apps/web/package.json` + `pnpm-lock.yaml` (add `@simplewebauthn/browser@^11`, `qrcode`, `@types/qrcode`)
- `apps/web/src/lib/crypto/aad-labels.ts` (add `AAD_LABEL_TOTP`)
- `apps/web/src/app/login/page.tsx` (soft router.push for 2FA branch + keyStore handoff)

---

## Next plans unblocked

- **Plan 03-12** (E2E Cypress: 2fa-webauthn / 2fa-totp / sessions /
  removal-guard / UX-copy regression). The full Phase-03 user surface
  is now wired end-to-end pending T4 visual confirmation.
