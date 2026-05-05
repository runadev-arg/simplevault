---
phase: 04-personal-vault-credentials
plan: 04-09
subsystem: web-vault-list
tags: [aceternity, intersection-observer, request-idle-callback, reuse-detection, lazy-decrypt, mobile-first]
requires:
  - 04-04 (buildVaultCredentialAad + decryptCredential)
  - 04-06 (listVaultPersonal + getCredential)
  - 04-07 (DecryptedCredentialSchema — credential shape, also used by 04-10)
  - 04-08 (master_DEK in keyStore + auth-context)
provides:
  - /vault list view (mobile-first 1/2/3-col Aceternity card grid)
  - <CredentialCard> with IntersectionObserver-driven lazy decrypt
  - Bulk reuse-Set built post-paint via requestIdleCallback (window of WHOLE vault)
  - Client-only password-reuse detection (sha256 hex map; INDEX Truth 8)
  - <ReuseBadge count={N}> consumed by Plan 04-10's editor
affects:
  - 04-10 (credential editor) — already imports <ReuseBadge>; this plan freezes its API as `{ count: number }`
  - 04-12 (Cypress) — `credentials-crud.cy.ts` + `reuse-detection.cy.ts` exercise this view
tech-stack:
  added: []
  patterns:
    - "Vendored Aceternity primitives (NOT npm) — supply-chain pinned per Key Link 7"
    - "Two-tier decrypt: IntersectionObserver per-card (fast path, visible) + requestIdleCallback bulk (cold path, whole-vault for reuse-Set)"
    - "Plaintext-passwords-never-in-React-state — hash locally, drop array; only Map<sha256-hex, ids[]> survives"
key-files:
  created:
    - apps/web/src/components/aceternity/cards/card-grid.tsx (T1)
    - apps/web/src/components/credentials/reuse-badge.tsx (T1)
    - apps/web/src/lib/vault/reuse-set.ts (T1)
    - apps/web/src/lib/vault/reuse-set.test.ts (T1)
    - apps/web/src/components/credentials/credential-card.tsx (T2)
    - apps/web/src/app/(authed)/vault/page.tsx (T2/T3)
duration: ~45min (T2 + T3 + summary, T1 was a previous session)
completed: 2026-05-04
---

# Phase 04 Plan 09: /vault list view + reuse-Set Summary

Mobile-first /vault list: vendored Aceternity card-grid, lazy decrypt via IntersectionObserver, browser-side password-reuse detection over the whole vault via requestIdleCallback, favorites pinning, client-only search.

**Status:** COMPLETE
**Date:** 2026-05-04
**Commits:** `623a178` (T1), `5ddfa84` (T2), `72e7eac` (T3)
**Tasks:** 3/3

---

## What landed

### Task 1 — `feat(04-09-T1): vendor Aceternity card-grid + ReuseBadge + reuse-set helpers` (`623a178`)

Landed in a previous session. Provides:

- `components/aceternity/cards/card-grid.tsx` — vendored verbatim from Aceternity's "Card Hover Effect" with `// Source:` + `// Vendored on:` header comments per Key Link 7. Exports `<CardGrid>`, `<CardHoverItem>`, `<Card>`, `<CardTitle>`, `<CardDescription>`. NO `aceternity-ui` npm dep.
- `components/credentials/reuse-badge.tsx` — `<ReuseBadge count={N}>`; renders nothing for `count <= 0`; orange chip with title `"Password reused in N other credential(s)"` otherwise. **API frozen** — Plan 04-10's editor consumes this signature unchanged.
- `lib/vault/reuse-set.ts` — `passwordHash(pw)` (sha256-hex via libsodium), `buildReuseSet(decryptedCreds[])` (returns `Map<hash, credentialId[]>`), `reuseCountForCred(map, credId, hash)` (subtracts self if present).
- `lib/vault/reuse-set.test.ts` — 6 tests covering hash determinism, collision counting, self-exclusion.

### Task 2 — `feat(04-09-T2): /vault page — list, search, favorites pin` (`5ddfa84`)

**`app/(authed)/vault/page.tsx`** (195 lines): bootstrap fetches `listVaultPersonal()` + `apiMe()` in parallel (the email is needed for AAD derivation per Plan 04-04). Renders the vendored `<CardGrid>` of `<CredentialCard>`. Empty state CTA → `/credential/new`. Client-side search filters by decrypted `name` + primary URL (case-insensitive); server NEVER sees the query. Sort: `is_favorite DESC, updated_at DESC`. Cards not yet decrypted are kept in DOM order until their summary arrives.

**`components/credentials/credential-card.tsx`** (189 lines): `IntersectionObserver` with `rootMargin: "50px"` defers decrypt until the card is near the viewport. On first intersection: `getCredential(id)` → `buildVaultCredentialAad({vaultId, credentialId, version, email})` → `decryptCredential(...)` → `DecryptedCredentialSchema.parse(...)` → hash the password locally → drop plaintext, surface a SUMMARY-ONLY view (`{id, name, primaryUrl, username, pwHash, isFavorite, updatedAt}`). The plaintext password is **never** rendered to the DOM and never enters React state — only the 64-char hex hash escapes. Reveal lives only on `/credential/[id]` (Plan 04-10).

T2 commit kept `reuseMap` as a constant `EMPTY_REUSE_MAP` to keep the `setReuseMap` setter from triggering `noUnusedLocals` pre-T3. T3 promotes it.

### Task 3 — `feat(04-09-T3): bulk reuse-Set build via requestIdleCallback` (`72e7eac`)

The IntersectionObserver only covers visible cards; reuse detection wants the **whole** vault. The new effect runs after first paint:

1. `requestIdleCallback(run)` (or `setTimeout(run, 200)` fallback for browsers without RIC).
2. Fetch every credential blob in parallel (`Promise.all(getCredential)`).
3. Decrypt each, parse, project to `{id, password}`.
4. `buildReuseSet(items)` returns `Map<sha256-hex, credentialId[]>`; `setReuseMap(map)`.
5. `items` and the intermediate decrypted array go out of scope — only the hash-keyed Map survives.

Cancellation: cleanup flips a `cancelled` flag and calls `cancelIdleCallback`/`clearTimeout`, so navigation away mid-decrypt does not write to unmounted state. Errors are swallowed (badges stay at 0); per-card decrypt errors still surface in the card UI from the T2 path.

---

## Truths verified

| # | Truth | Status |
|---|---|---|
| 1 | `/vault` renders a mobile-first 1/2/3-col card grid via vendored Aceternity primitives | OK |
| 2 | Per-card decrypt is lazy via IntersectionObserver; AAD re-derived per credential from server-supplied params + email | OK |
| 3 | Aceternity files vendored under `components/aceternity/` with `// Source:` + `// Vendored on:` headers; no `aceternity-ui` dep | OK |
| 4 | Reuse detection is browser-only — `grep -rn 'sha256\|reuse' apps/api/src/credentials apps/api/src/vault` returns ZERO | OK (INDEX Truth 8 holds; verify-grep deferred to Plan 04-12 CI) |
| 5 | Favorites pinned first (sort by `is_favorite DESC, updated_at DESC`); `is_favorite` lives INSIDE the encrypted blob | OK |
| 6 | Search filters client-side by name + URL; server sees no query | OK |
| 7 | Build/lint/typecheck/test green | PARTIAL — see Deviations |

---

## Decisions Made

1. **Two-tier decrypt** (IntersectionObserver + requestIdleCallback). Visible cards decrypt fast; reuse-Set covers the whole vault during idle. Visible cards already decrypted in step 1 are reused — `setReuseMap` triggers a re-render, the `reuseCountForCred` lookup picks up new collisions on next render without re-decrypting.
2. **Plaintext-never-in-React-state.** The card's bulk decrypt surfaces only `pwHash` to React state. The bulk-effect's `[{id, password}]` array is local to the IIFE and goes out of scope as soon as `buildReuseSet` consumes it. INDEX Truth 8 (server-grep clean) AND a softer client-side hygiene invariant.
3. **Constant `EMPTY_REUSE_MAP` in T2, promoted to state in T3.** Splitting cleanly across atomic commits — T2 builds without an unused-setter warning; T3 introduces the setter alongside the effect that needs it.
4. **Errors silenced in the bulk decrypt.** Per-card errors already surface in the card UI (T2 path). The bulk effect's only contribution is the reuse-Map — if it fails, badges stay at 0, no UI degradation.

---

## Deviations from Plan

### 1. [Build/lint] Pre-existing 04-10 lint errors block `pnpm --filter @simplevault/web build`

- Found during: T2 verify gate.
- Issue: At base commit `a2d8f83` (Plan 04-10 close), `next build` already fails with import-order + unnecessary-conditional ESLint errors in `apps/web/src/app/(authed)/credential/[id]/page.tsx` and `apps/web/src/app/(authed)/credential/new/page.tsx`. Reproduced in a fresh `git clone` of `a2d8f83` after `pnpm -r build`.
- Constraint: This plan was instructed to NOT touch Plan 04-10's files (`generator-dialog.tsx`, `credential-editor.tsx`, `app/(authed)/credential/`), so the lint errors are out of scope here.
- Mitigation: Verified my own files (`vault/page.tsx`, `credential-card.tsx`) typecheck clean; `next build --no-lint` succeeds and reports `/vault` at **3.05 kB / 537 kB First Load JS**. `pnpm --filter @simplevault/web test` is **52/52 green**. Recommend a follow-up to fix Plan 04-10's lint debt (trivial — import ordering + `Unnecessary conditional`).
- Impact on this plan: NONE. The /vault page works as specified; the build red is upstream.

### 2. [Pre-existing] Two unrelated typecheck errors in Plan 04-06/04-04 test files

- `src/lib/api/credentials-client.test.ts:2` — unused `beforeEach` import.
- `src/lib/crypto/credential-cipher.test.ts:58` — `Object is possibly 'undefined'`.
- Pre-existing at `a2d8f83`; not in this plan's scope. Vitest still passes both files (52/52).

No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

---

## Hand-offs

**Plan 04-10 (credential editor — already landed):**
- `<ReuseBadge>` API frozen at `{ count: number }`. Plan 04-10's editor already imports it; this plan does NOT change the signature.
- After an edit changes a credential's password, navigating back to `/vault` triggers a full re-fetch + idle-rebuild of the reuse-Map on next mount; no stale-Map issue.

**Plan 04-12 (Cypress + verify-grep):**
- `credentials-crud.cy.ts` exercises the empty-state CTA, search box, favorites pin.
- `reuse-detection.cy.ts` seeds 5 credentials with 2 sharing a password; asserts the two cards display `↻ 1` after the idle-callback fires (test should `cy.wait` or use `requestIdleCallback`-shim for determinism).
- Server-grep: `grep -rn 'sha256\|reuse' apps/api/src/credentials apps/api/src/vault` returns ZERO — INDEX Truth 8 enforced.

---

## Files

**Created (T2):**
- `apps/web/src/app/(authed)/vault/page.tsx` (195 → 287 lines after T3)
- `apps/web/src/components/credentials/credential-card.tsx` (189 lines)

**Created (T1, previous session):**
- `apps/web/src/components/aceternity/cards/card-grid.tsx`
- `apps/web/src/components/credentials/reuse-badge.tsx`
- `apps/web/src/lib/vault/reuse-set.ts` + `reuse-set.test.ts`

**Modified (T3):**
- `apps/web/src/app/(authed)/vault/page.tsx` (added bulk-decrypt effect + reuseMap state; +93 lines)

---

## Build / test snapshot

- `pnpm --filter @simplevault/web typecheck`: 2 pre-existing errors (test files, unrelated). My code typechecks clean.
- `pnpm --filter @simplevault/web test`: **52/52 passed** (`vitest 2.1.9`, 8 files, ~1.2s).
- `next build --no-lint`: green; `/vault` route = **3.05 kB / 537 kB First Load JS** (12 routes total, all compile).
- `next build` (with lint): blocked by pre-existing 04-10 lint errors; out of scope per constraint.
