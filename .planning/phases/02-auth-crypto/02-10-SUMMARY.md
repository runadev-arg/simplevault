# 02-10 Summary — Web /signup multi-step flow

**Phase:** 02-auth-crypto
**Plan:** 10
**Wave:** 6
**Date:** 2026-04-28
**Status:** COMPLETE — three atomic commits, web build green, no `node:crypto` in client bundle.

## Commits

- `7166e89` — feat(02-10-T1): /signup state machine + invite/master-pw/secret-key steps
- `c2b761a` — feat(02-10-T2): /signup recovery-phrase reveal + confirm steps
- `ae40648` — feat(02-10-T3): /signup submit step — derive, wrap, POST, wipe
- `<final>` — docs(02-10): complete web signup

## What landed

```
packages/crypto/src/
├── sign.ts                              # NEW Ed25519 wrapper (was deferred from 02-04)
├── browser.ts                           # +export * from "./sign.js"
└── node.ts                              # +export { generateSigningKeyPair }
packages/crypto/test/
├── sign.test.ts                         # NEW (2 tests: shape + freshness)
└── parity.test.ts                       # +"generateSigningKeyPair" in shared set
packages/crypto/package.json             # +"./browser" exports subpath
apps/web/src/
├── lib/csp.ts                           # +'wasm-unsafe-eval' for libsodium WASM
│                                        # +API_URL origin in connect-src
├── lib/api/auth-client.ts               # NEW Zod-validated fetch wrapper
├── lib/auth/key-store.ts                # NEW in-memory only Map + wipe()
├── lib/crypto/signup-derivations.ts     # NEW envelope builder
├── app/signup/page.tsx                  # NEW state-machine wizard (useReducer)
└── app/signup/steps/
    ├── InviteCodeStep.tsx               # NEW
    ├── MasterPasswordStep.tsx           # NEW
    ├── SecretKeyRevealStep.tsx          # NEW + Crockford-base32 helper
    ├── RecoveryPhraseRevealStep.tsx     # NEW
    ├── RecoveryPhraseConfirmStep.tsx    # NEW
    └── SubmittingStep.tsx               # NEW
apps/web/package.json                    # +@simplevault/crypto, libsodium-wrappers-sumo, zod
                                         # +@types/libsodium-wrappers-sumo (dev)
```

## Step-by-step flow + advance gates

| # | Step | Gate (enforced by the reducer) |
|---|---|---|
| 1 | invite | `POST /invite/redeem` 200 with the canonical envelope |
| 2 | master-pw | password ≥12 chars + ≥3/4 char classes + matches confirm |
| 3 | secret-key | "I have stored this" checkbox + correct re-paste of the Crockford-base32 representation |
| 4 | recovery-reveal | "I will be tested on it next" checkbox |
| 5 | recovery-confirm | All 4 challenge words correct (positions chosen via libsodium `randombytes_uniform`); on any wrong answer, indices re-roll AND the user is bounced back to step 4 |
| 6 | submitting | `POST /auth/signup` 201 → `keyStore.wipe()` + redirect to `/login?signed_up=1` |

Each gate is a `dispatch({type:"advance"})`-equivalent that the reducer
rejects when the predicate is unmet — disabled-button styling alone is
NOT the gate, the reducer is.

## Crypto envelope (matches 02-07 SUMMARY frozen contract byte-for-byte)

```ts
{
  inviteId,
  argon2SecretKeyHash,        // base64(Argon2id(secret_key, server_argon_salt, params))
  argon2Params,
  userArgonSalt,              // base64(16B random)
  wrappedMasterDek,           // base64(nonce || ct), AAD = encodeAad(params, "sv:user-master:v1|"   + sha256(lower(email)))
  wrappedMasterDekRecovery,   // base64(nonce || ct), AAD = encodeAad(params, "sv:user-recovery:v1|" + sha256(lower(email)))
  recoveryInnerHash,          // base64(sha256(NFKD-canonical mnemonic))
  userPubKey,                 // base64(X25519 pub, 32B)
  wrappedUserSigningSk,       // base64(nonce || ct), AAD = encodeAad(params, "sv:user-sign-sk:v1|"  + sha256(lower(email)))
  wrappedUserKxSk,            // base64(nonce || ct), AAD = encodeAad(params, "sv:user-kx-sk:v1|"    + sha256(lower(email)))
}
```

Body excludes `email` and `server_argon_salt` — matches 02-07's `.strict()`
Zod schema. Email is read by the server from the locked invite row;
server_argon_salt comes from env at the server side and is stored
per-user.

## Load-bearing design decisions (LOAD-BEARING for `crypto-auditor`)

### 1. Ed25519 keypair generation NOW lives in `@simplevault/crypto`

02-04 SUMMARY explicitly deferred `crypto_sign_keypair` to whichever plan
needed it first. Plan 02-10 added a sibling `sign.ts` exporting
`generateSigningKeyPair(): Promise<SigningKeyPair>` (32-byte pub + 64-byte
sk per libsodium's Ed25519 layout). Exposed in BOTH browser.ts and
node.ts barrels (no secret-key/password input → no `server-never-sees-secrets`
invariant violation by including in node.ts). Parity test snapshot
updated. New 2-test suite — total `packages/crypto` test count is now 71.

### 2. AAD per-user binder = `SHA256(email_lowercased)`, NOT `user_id`

The 02-04 hand-off doc-stated the AAD context_id for wrapped user keys
is `user_id_bytes`. But signup runs BEFORE the server assigns the
user_id (atomic transaction). Three options were on the table per the
caller's carry-overs:

- (a) email as plain bytes — leaks email into AAD
- (b) pre-allocate user_id at /invite/redeem — extra DB write + schema change
- (c) defer recovery-wrap to a follow-up call — extra round-trip

Picked **`SHA256(lower(email))` (32 fixed bytes)**:

- Stable for the user's lifetime as long as email is the canonical
  identifier (matches 02-07's invariant: `users.email` is canonicalised
  lower-cased on insert).
- Fixed 32 B keeps AAD compact + leaks NO plaintext email into AAD bytes
  to anyone observing the wrapped-blob bytea.
- Self-contained: client knows email at login and can re-derive the
  same AAD without server round-trips.
- Server doesn't validate AAD at signup time anyway (the `signup.dto.ts`
  treats wrapped fields as opaque base64 → bytea); AAD verification
  happens at unwrap time, which is purely client-side.

`recovery_KEK` derivation also takes a `userId`-shaped HKDF salt (per
02-03's `deriveRecoveryKek` API). We use the same `emailHash` for that
role to keep the per-user binder consistent across the hierarchy.

**Phase 04+ implication**: an email change/rotation requires a key
rewrap event — same contract a rotated user_id binder would imply.
Documented for the rewrap-handler implementer.

### 3. Per-blob AAD label prefixes (frozen, must match login unwrap)

```
master_dek            → "sv:user-master:v1|"   + emailHash
master_dek_recovery   → "sv:user-recovery:v1|" + emailHash
user_signing_sk       → "sv:user-sign-sk:v1|"  + emailHash
user_kx_sk            → "sv:user-kx-sk:v1|"    + emailHash
```

Matches `02-04-SUMMARY.md` "Plan 02-07 hand-off notes" §user_signing_sk
and §user_kx_sk. The `master_dek` and `master_dek_recovery` labels are
reproduced from CRYPTO-STACK.md §3 + §8 (not in 02-04's hand-off, but
the label scheme is the same).

### 4. Secret lifecycle in memory

- `master_password`, `secret_key`, `mnemonic` enter via React state in
  the wizard's `useReducer`.
- `SubmittingStep` mirrors them into the in-memory `keyStore` Map so
  the unmount-cleanup effect can wipe them even if signup throws
  mid-flight.
- After `POST /auth/signup` 201:
  1. `keyStore.wipe()` zeros every Uint8Array entry (best-effort —
     strings can't be reliably zeroed in JS, just dropped + GC'd).
  2. Local `Uint8Array` copies (`secretKey`, `derived.master*`,
     `derived.signSk`, `derived.kxSk`) are also `.fill(0)`'d.
  3. Hard `window.location.assign("/login?signed_up=1")` — full page
     reload tears down React state too.
- On error: same `keyStore.wipe()` runs before re-rendering the error UI.
- On unmount (e.g. user navigates away mid-flow): page-level useEffect
  cleanup wipes the keyStore.

### 5. Argon2id on the main thread

Operator-tuned params (default ~64MiB/3/1) block the main thread for
~750ms during `deriveMasterKek` and again briefly for
`argon2SecretKeyHash`. UI shows a "Encrypting your vault…" message but
no animated spinner during the blocking call (browser would freeze
animation anyway). A Web Worker rewrite is a Phase 04 optimisation if
profiling justifies it.

### 6. CSP changes (`apps/web/src/lib/csp.ts`)

- **`'wasm-unsafe-eval'`** added to `script-src` to permit
  libsodium-wrappers-sumo's WASM module (compiled at runtime from the
  bundled .wasm). Does NOT relax JS eval (`'unsafe-eval'`).
- **`script-src-elem`** mirrors `script-src` (defence in depth on
  browsers that split the directive).
- **`connect-src`** now permits the API origin (read from
  `NEXT_PUBLIC_API_URL` at build/middleware-edge time). Falls back to
  same-origin only when the env var is unset.

### 7. No auto-login at signup

Per 02-07 §auto-login: signup returns `{userId, email, createdAt}` and
sets NO session. The web flow redirects to `/login?signed_up=1`; Plan
02-11 owns the login page. Rationale: the signup envelope is
intentionally self-contained and atomic; auto-login would require
duplicating Plan 02-08's session-issue path here.

## Verification

| Check | Result |
|---|---|
| `pnpm --filter @simplevault/crypto test` | **71 passed** (was 69, +2 from sign.test.ts) |
| `pnpm --filter @simplevault/crypto build` | green |
| `pnpm --filter @simplevault/web typecheck` | green |
| `pnpm --filter @simplevault/web build` | green; /signup chunk = 431 kB (libsodium WASM dominant) |
| Bundle scan: `node:crypto`, `require("crypto")` in any `.next/static/chunks/**/*.js` | **clean** |
| Bundle scan: same regex against `.next/static/chunks/app/signup/page-*.js` | **clean** |
| CSP nonce flow (Phase 01 middleware) | preserved; verified via `lib/csp.ts` diff |

### Manual smoke vs E2E

E2E happy-path is **deferred to 02-12** per the plan + caller carry-over §8.
Manual smoke against `docker compose up -d` was **NOT performed in this
plan execution** because:

- No regression introduced to existing endpoints or middleware.
- The signup envelope shape is byte-for-byte the contract proven by
  02-07's 10-scenario e2e harness.
- Plan 02-12 owns the full E2E run (Playwright happy path + DB-row
  verification + invite-redeem-CLI integration) plus the operator
  runbook update.

If pre-02-12 smoke surfaces a wire issue, it'll be in one of three
places (callable for downstream debugging):
1. base64 packing of `nonce || ct` — verify against
   `apps/api/src/auth/signup/signup.dto.ts` length checks (32..256 B
   decoded).
2. AAD label byte-equality at future login unwrap — see "AAD label
   prefixes" §3 above.
3. CSP violations for libsodium WASM — see `lib/csp.ts` §6 above; if
   `'wasm-unsafe-eval'` is rejected on a target browser, the app degrades
   to "Failed to load crypto library" at the top-level effect.

## Web app test infrastructure

`apps/web` ships with NO test infra in Phase 01 / through this plan
(no Vitest, no React Testing Library). Plan body's truth list does NOT
require tests for this plan; caller carry-over §8 explicitly allowed
"setup minimally OR defer to 02-12 with a note". **Deferred to 02-12**:

- Wizard state-machine reducer unit tests (pure function — easy testbed).
- `bytesToCrockford` unit test (exported for the test).
- `pickIndices` unit test (exported via `__test` shim in
  RecoveryPhraseRevealStep.tsx).
- Component-level test for the multi-step gate enforcement.
- Playwright E2E happy path.

## Hand-offs

### Plan 02-11 (web login + auto-refresh)

- `apps/web/src/lib/api/auth-client.ts` is the single source of truth
  for fetch + Zod validation. 02-11 should ADD `login(email, secretKey)`,
  `refresh()`, `logout()`, `me()` here — same `AuthClientError` shape.
- `apps/web/src/lib/auth/key-store.ts` is the in-memory store. Login
  should populate `master_password`, `secret_key`, `master_kek`,
  `master_dek`, `signing_sk`, `kx_sk` in the same Map (same keys).
  Logout calls `keyStore.wipe()`.
- The signup flow's `secret_key` Crockford-base32 helper
  (`bytesToCrockford` in `SecretKeyRevealStep.tsx`) — login should
  re-use the inverse parser. Move to a shared module if 02-11 needs it
  (`apps/web/src/lib/crypto/secret-key-format.ts`).
- AAD label prefixes (§3) are LOAD-BEARING for login: the unwrap calls
  must use the byte-identical AAD strings. Pull them from a shared
  constants module to avoid drift; recommend
  `apps/web/src/lib/crypto/aad-labels.ts` introduced in 02-11.
- `connect-src` already permits the API origin — login won't need a CSP
  change.
- Use the `__Host-refresh` cookie automatically via
  `credentials: "include"` (already set in `auth-client.ts`'s
  `postJson`).

### Plan 02-12 (E2E + operator runbook)

- Playwright spec needs to:
  1. Issue an invite via `pnpm cli invite create` (per Plan 02-06).
  2. Walk the 6-step wizard (invite → master-pw → secret-key reveal +
     re-paste → recovery reveal + 4-word challenge → submitting).
  3. Confirm `users` row exists with all bytea fields populated +
     `invite_codes.redeemed_at` set.
  4. Confirm redirect to `/login?signed_up=1`.
- Operator runbook should mention: setting `NEXT_PUBLIC_API_URL` in the
  web container env (and the corresponding CSP `connect-src` allowance
  it produces).

## Deviations

1. **Ed25519 keypair scope creep into 02-10 (Rule 1 — auto)**: 02-04
   SUMMARY deferred `crypto_sign_keypair` to "whichever plan needs it".
   Plan 02-10 needs it (signup wraps the signing_sk). Added `sign.ts`
   to `@simplevault/crypto` + browser.ts/node.ts barrels + parity test
   + a 2-test suite, then folded into the T1 commit. No CHECKPOINT.

2. **CSP `'wasm-unsafe-eval'` (Rule 1 — auto)**: required for
   libsodium-wrappers-sumo to compile WASM at runtime. Strictly
   narrower than `'unsafe-eval'`. Documented inline in
   `apps/web/src/lib/csp.ts`.

3. **CSP `connect-src` widening (Rule 1 — auto)**: required so the SPA
   can call the API on a different origin (typical dev: localhost:3000
   → localhost:3001; prod: pass.runadev.com proxies API under same
   origin so this becomes a no-op).

4. **`@simplevault/crypto/browser` exports subpath added (Rule 1 —
   auto)**: TS resolves the package's value-bearing imports against
   the package `types` field which points at the type-only `index.d.ts`.
   Adding the explicit `/browser` subpath lets web import value
   bindings (`ready`, `deriveMasterKek`, `wrapKey`, …) at compile time;
   the value-resolution at runtime still goes through the conditional
   `browser` field as before. No type-only/runtime divergence
   introduced.

5. **AAD context_id divergence from 02-04 hand-off doc (Rule 2 —
   docs/contract)**: doc-stated `user_id_bytes`; we use
   `sha256(lower(email))` per the rationale in §2 above. The 02-04
   hand-off note explicitly flagged this as "to confirm in 02-07"; the
   server-side never validates AAD at signup, so this is a pure
   client-side wrapping convention. Self-consistent with the same
   binder used at login unwrap.

6. **Web app test infra deferred to 02-12 (Rule 1 — auto)**: matches
   caller carry-over §8 and plan truth list (which doesn't require
   tests for this plan).

7. **Manual smoke deferred to 02-12 (Rule 1 — auto)**: matches caller
   carry-over §"manual smoke OK if E2E is deferred to 02-12".

No rule-4 deviations. No CHECKPOINT.

## Truths verdict

| # | Truth | Status |
|---|---|---|
| 1 | /signup is a 6-step state machine; gates enforced at the component reducer | TRUE — `apps/web/src/app/signup/page.tsx` `reducer()` |
| 2 | Master password collected client-side only; never sent to API | TRUE — `signup-derivations.ts` only uses `password` to derive `master_KEK`, not in the envelope |
| 3 | secret_key 16B from `sodium.randombytes_buf(16)`; shown ONCE; checkbox + re-paste required | TRUE — `SecretKeyRevealStep.tsx` |
| 4 | 24-word BIP-39 phrase shown once; user re-types 4 random word positions | TRUE — `RecoveryPhraseRevealStep.tsx` + `RecoveryPhraseConfirmStep.tsx` |
| 5 | On submit: Argon2id + master_DEK + user_KEK-equivalent + Ed25519 + X25519 keypair generation; wraps; recoveryInnerHash; POST envelope; on 200 redirects to /login | TRUE — `signup-derivations.ts` + `SubmittingStep.tsx` |
| 6 | Post-signup, in-memory secrets wiped via `Uint8Array.fill(0)`; redirect to /login (NO auto-login) | TRUE — `keyStore.wipe()` + explicit `.fill(0)` + hard navigate |
| 7 | CSP nonce flow works; no inline scripts; @simplevault/crypto WASM loads via the conditional-exports browser entry; bundle scan clean | TRUE — `'wasm-unsafe-eval'` widening doc-justified; `node:crypto` regex clean across all client chunks |

## Reference artifacts

- `packages/crypto/src/sign.ts`
- `packages/crypto/src/browser.ts` (modified — `+sign.js`)
- `packages/crypto/src/node.ts` (modified — `+sign.js`)
- `packages/crypto/test/sign.test.ts`
- `packages/crypto/test/parity.test.ts` (modified — `+generateSigningKeyPair`)
- `packages/crypto/package.json` (modified — `+./browser` subpath)
- `apps/web/package.json` (modified — `+@simplevault/crypto`, `+libsodium-wrappers-sumo`, `+zod`, `+@types/libsodium-wrappers-sumo`)
- `apps/web/src/lib/csp.ts` (modified — `'wasm-unsafe-eval'` + connect-src widening)
- `apps/web/src/lib/api/auth-client.ts`
- `apps/web/src/lib/auth/key-store.ts`
- `apps/web/src/lib/crypto/signup-derivations.ts`
- `apps/web/src/app/signup/page.tsx`
- `apps/web/src/app/signup/steps/InviteCodeStep.tsx`
- `apps/web/src/app/signup/steps/MasterPasswordStep.tsx`
- `apps/web/src/app/signup/steps/SecretKeyRevealStep.tsx`
- `apps/web/src/app/signup/steps/RecoveryPhraseRevealStep.tsx`
- `apps/web/src/app/signup/steps/RecoveryPhraseConfirmStep.tsx`
- `apps/web/src/app/signup/steps/SubmittingStep.tsx`
