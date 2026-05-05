---
phase: 04-personal-vault-credentials
plan: 04-10
title: /credential/new + /credential/[id] forms — generator + meter + history rotation + clipboard stub
status: closed
commits:
  - 282b6a9 feat(04-10-T1): credential-shape Zod + GeneratorDialog (dynamic-imported)
  - 7ca7736 feat(04-10-T2): /credential/new — create flow with client-chosen UUID + AAD self-consistency
  - cea40c0 feat(04-10-T3): /credential/[id] — edit flow + history rotation + 409 retry
---

# Plan 04-10 — close

## Truths landed

1. **Editor surface (REQ-VAULT-002)**: `apps/web/src/components/credential-editor.tsx` renders all required fields — `name` (required, max 200), `urls[]` (multi-add chips, max 10, URL-validated), `username`, `password` (input + reveal toggle + Generate button + StrengthMeter inline + ReuseBadge from sibling Plan 04-09), `notes` (textarea), `custom_fields[{name,value,hidden}]` (repeatable, max 20), `is_favorite`. The two route pages (`/credential/new`, `/credential/[id]`) are thin orchestrators that pull `master_DEK` from `keyStore`, fetch `/vault/personal` + `/me` for context (vaultId + email for AAD), and delegate the form to `<CredentialEditor>`.

2. **Generator dialog (Plan 04-05 consumer)**: `components/generator-dialog.tsx` exposes two tabs — **password** (length 8..128 slider + four class checkboxes; defaults length=20, all on) and **passphrase** (wordCount 3..10 + separator; defaults 5, "-"). Live preview re-generates on input change. "Use this" writes the value into the editor's password field and closes. The dialog is dynamic-imported via `next/dynamic({ssr:false})` so the EFF-large wordlist (~60 KiB) stays out of the editor's First Load JS until the dialog opens.

3. **Create flow with client-chosen UUID (closes the AAD self-consistency gap)**: `/credential/new` calls `crypto.randomUUID()` to mint the credential id LOCALLY, encrypts with that id baked into the AAD's canonical-JSON, and POSTs both `vaultId` AND `credentialId` to the server. Plan 04-02's `createCredential` wrapper already accepts the optional `credentialId` field (verified at `apps/web/src/lib/api/credentials-client.ts:90`). This removes the two-roundtrip "encrypt with placeholder → POST → re-encrypt with server id" antipattern.

4. **Edit flow + history rotation (REQ-VAULT-006 / INDEX truth 12)**: `/credential/[id]` decrypts the existing blob using the server-current version's AAD. On save, the page bumps `version` (baseline + 1), and IF the password changed, prepends `{password: previous, changedAt: ISO}` to `history[]` and `slice(0, 10)`-caps. The schema `DecryptedCredentialSchema.history.max(10)` validates again at re-encryption. **Old plaintext NEVER exits the encrypted blob** — the server only ever sees ciphertext + nonce + canonical AAD JSON.

5. **409 retry-or-cancel UX (NOT silent)**: PATCH catches `VersionConflictError`, re-fetches via `getCredential`, re-decrypts with the FRESH version's AAD, re-validates via Zod, and prompts: *"This credential was updated elsewhere. Apply your edits on top of the latest version?"* On confirm, `saveWithBaseline` recurses with the fresh baseline (so the new PATCH sends `version: fresh.version` as the CAS witness and writes `fresh.version + 1`). On cancel, the page surfaces a typed-error message and leaves the form populated with the LATEST decrypted state — the user can re-merge manually and resubmit.

6. **Clipboard-clear stub (browser-honest)**: `lib/vault/clipboard-stub.ts:copyPasswordWithClear(pw, ms = 30_000)` calls `navigator.clipboard.writeText(pw)` then schedules `setTimeout(() => navigator.clipboard.writeText(""), 30_000)`. Both the source-comment and a visible inline help-text below the password row spell out the limitation: **browsers cannot truly purge the OS clipboard once the user pastes elsewhere; this is a defence-in-depth stub.** Phase-12 forward-flag: the final CSP must permit `navigator.clipboard.writeText` (it works under default CSP).

## Cross-plan handoffs

- **Plan 04-02 DTO patch (already in place)**: `CredentialCreateSchema` accepts the optional `credentialId` (verified by Plan 04-06's typed wrapper at `credentials-client.ts:88-93,134`). No further edit needed.
- **Plan 04-09 (sibling Wave 4)**: We import `<ReuseBadge>` from `apps/web/src/components/credentials/reuse-badge.tsx` (sibling-owned) — the file exists and was committed in 623a178. No redundant `reuse-chip.tsx` was created. The editor accepts `reuseCount` as a prop; the route pages pass `0` for `/credential/new` (no id yet) and could be wired to the vault-wide reuse-set in a follow-up (Plan 04-12 / Cypress will exercise this end-to-end).
- **Plan 04-12 Cypress**: `credentials-crud.cy.ts` will exercise create → edit → 409 → delete; `password-generator.cy.ts` covers the dialog tabs + "Use this"; `auto-lock.cy.ts` exercises in-flight editor + idle lock interaction.

## Bundle (next build)

```
Route (app)                   Size   First Load JS
/credential/new              985 B           539 kB
/credential/[id]            1.52 kB          539 kB
/vault                      3.03 kB          537 kB   (sibling 04-09)
+ First Load JS shared       102 kB
```

Generator-dialog code lives in a route-async chunk (split via `next/dynamic`) — verified by absence from the route's First Load JS surface (the +1 kB delta over the Plan-04-09 baseline is form-state only; the EFF wordlist resolves on first dialog open). The editor's 539 kB First Load JS includes the StrengthMeter dynamic-load shell (the dictionary itself is also lazy).

## Deviations / forward-flags

- **Email storage**: Plan suggested `keyStore.get("email")`. We chose to fetch `/me` once on page-mount (cheap; the response is small + already cache-warmed for an authed session). Avoided modifying the login flow to stash email in keyStore. Trade-off: one extra `/me` round-trip on each editor open; gain: zero cross-plan coupling.
- **shadcn / Radix not adopted**: `apps/web` does not depend on either. The GeneratorDialog uses a native role="dialog" overlay + ESC-to-close + outside-click-to-close. Tailwind + ARIA carry the a11y. If Phase 05 adopts shadcn we revisit.
- **Optimistic baseline bump on success**: After a successful PATCH the page rewrites the local `baseline.version` to the new value before navigating to `/vault`. If the navigate is intercepted (offline / aborted), the user can keep editing without a stale CAS witness.
- **`reuseCount` prop wiring**: The editor accepts the prop but the two route pages currently pass none (defaults to 0). End-to-end vault-wide reuse highlighting on the editor is a Plan 04-09 / 04-12 follow-up — the surface is intentional so no API churn is needed when the vault page passes the precomputed map down.

## Verification

- `pnpm --filter @simplevault/web test` — 8 files / **52 tests pass**.
- `pnpm --filter @simplevault/web exec next build --no-lint` — green; routes built. Build linting failures observed during the run come from sibling Plan 04-09 files (`aceternity/cards/card-grid.tsx`, `credentials/reuse-badge.tsx`, `lib/vault/reuse-set.ts`) — out of scope for this plan; they are sibling-owned.
- Pre-existing typecheck noise (`credentials-client.test.ts: beforeEach unused`, `credential-cipher.test.ts: TS2532`) is not introduced by Plan 04-10 — confirmed by checking baseline before any edits.
