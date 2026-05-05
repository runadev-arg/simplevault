# Phase 05 — Personal vault: rich-text pages (TipTap) (Index + Wave Map)

**Goal (must be TRUE):** A logged-in user can create, view, edit, and delete TipTap rich-text pages in their personal vault; pages encrypt client-side under `master_DEK`; server stores ciphertext + a per-page `title_search_token` (8-byte HMAC prefix) and serves title-prefix search; last 10 ciphertext versions are kept server-side; the strict TipTap schema (paragraph, h1-h3, lists, blockquote, code, marks, sanitized links) is enforced client-side and a defensive `sanitize-html` pass runs at render. No images/tables/embeds in v1.

> **Builds on Phase 04.** AAD scheme `sv:vault-credential:v1|` extends with a sibling `sv:vault-page:v1|` label binding `(vaultId ‖ pageId ‖ version)` over the same email-hash + canonical-JSON envelope (Plan 04-04 SUMMARY contract). `master_DEK` (in-memory `keyStore`, populated at `/login`) is the wrap key — server still cannot decrypt. CAS-PATCH primitive, uniform-404 anti-enum posture, body-size cap pattern, and `.strict()` Zod DTOs are reused verbatim from Phase 04. The `vaults` table + `getOrCreatePersonalVault` join pattern (Plan 04-01/03) is the parent for the new `pages` FK.

## Goal-backward truths

1. `GET /pages?q=<prefix>` (auth required) returns `[{id, vaultId, version, titleSearchToken, isLocked, updatedAt}]` for the caller's personal vault. `q` is an optional 16-hex-char prefix (8-byte HMAC); when present, server filters `WHERE title_search_token LIKE $prefix || '%'`. No `q` → returns all pages (no pagination in v1; ≤50-user / ~hundreds-of-pages scale).
2. `POST /pages` accepts `{vaultId, ciphertext, nonce, aadParamsJson, titleSearchToken: bytea(8), version: 1}`; server validates vault ownership, inserts page, returns `{id, vaultId, version: 1, titleSearchToken, isLocked: false, updatedAt}`. Rejects bodies > 256 KiB (page bodies are larger than credentials).
3. `GET /pages/:id` returns full envelope `{id, vaultId, version, ciphertext, nonce, aadParamsJson, titleSearchToken, isLocked, updatedAt}`. Cross-user / not-found → uniform 404 `PAGE_NOT_FOUND`.
4. `PATCH /pages/:id` runs the same atomic CAS pattern as credentials: `WHERE id=$id AND vault_id IN (... owner=$user) AND version=$current`; zero rows → 409 `PAGE_VERSION_CONFLICT`. On success, INSERT a `page_versions` row with the PRE-update ciphertext/nonce/aad/version, then DELETE oldest rows for that `page_id` if count > 10. Single transaction.
5. `DELETE /pages/:id` hard-deletes (FK-cascades `page_versions`). Returns 204. Uniform 404 on cross-user.
6. `GET /pages/:id/history` returns `[{version, ciphertext, nonce, aadParamsJson, createdAt}]` (last 10, ordered descending by version) for the caller's pages only. Client decrypts each to render version diffs.
7. **AAD label = `"sv:vault-page:v1|"` (FROZEN).** `buildVaultPageAad({vaultId, pageId, version, email})` mirrors `buildVaultCredentialAad` exactly: `utf8(label) || sha256(lower(email)) || canonicalJson({pageId, vaultId, version})` (alphabetical keys). Lives in `aad-labels.ts` next to existing labels; browser-only export. Parity test (`aad-parity.test.ts`) extends to ban inline `"sv:vault-page:v1|"` literals outside `aad-labels.ts`.
8. **Title-search HMAC is client-derived.** `title_search_key = HKDF-Expand(master_DEK, "sv:title-search:v1", 32)`; `title_search_token = HMAC-SHA256(title_search_key, lower(title)).slice(0, 8)`. Computed in browser before POST/PATCH; 8-byte prefix → ~2³² bucket space (acceptable leakage at ≤50-user scale per REQ-VAULT-010). HKDF info string FROZEN.
9. **Server NEVER validates TipTap JSON.** TipTap document lives INSIDE the ciphertext (server can't see it). Server validates only the envelope shape: `{ciphertext: bytes, nonce: bytes(24), aadParamsJson: string ≤2 KiB, titleSearchToken: bytes(8), version: int}`. Document this loudly; REQ-VAULT-008 schema enforcement is a CLIENT contract.
10. **TipTap strict schema (client).** Allowed nodes: `paragraph`, `heading` (levels 1-3), `bulletList`, `orderedList`, `listItem`, `blockquote`, `codeBlock`, `text`. Allowed marks: `bold`, `italic`, `strike`, `underline`, `code`, `link` (href validated against `^https?://` ONLY; `javascript:`, `data:`, `vbscript:`, anything else → stripped at parse time). NO `image`, `table`, `iframe`, `hardBreak` HTML embed. TipTap `Schema` instance constructed once, exported from `apps/web/src/lib/tiptap/schema.ts`.
11. **Defensive render sanitization.** Even with the strict schema, render passes through `sanitize-html` with a tight allowlist (mirror of TipTap schema) before reaching React. Never `dangerouslySetInnerHTML` against raw TipTap output; render via TipTap's own React reconciliation primitives + `sanitize-html` on serialized HTML for the read-only history-diff view. (REQ-WEBSEC-005.)
12. **Favorites flag in encrypted blob.** `isFavorite: bool` lives INSIDE the TipTap-document wrapper (e.g. `{tiptap: {...}, meta: {isFavorite, createdAt}}`). NOT a server column. UI pin/sort happens client-side. Mirrors REQ-VAULT-011 / Phase-04 favorites posture.
13. **Server cannot decrypt — grep gate extends.** `grep -rn "ciphertext\|aead\|decrypt" apps/api/src/pages` returns ZERO calls into `@simplevault/crypto`. The `pages` module imports DB primitives only.
14. **Single-locked default.** `is_locked` column exists, defaults `false`, and Phase 05 ships only the `false` state. Phase 06 (deferred under MVP track) adds the double-lock mechanics; the column is a forward-compat hook.

## Required artifacts (high level)

- `packages/db/src/schema/`: NEW `pages.ts` (id, vault_id FK, version, ciphertext, nonce, aad_params_json, title_search_token bytea(8), is_locked bool default false, created_at, updated_at; `index(vaultId)`, `index(titleSearchToken)`); NEW `page_versions.ts` (id, page_id FK cascade, version, ciphertext, nonce, aad_params_json, created_at; `index(pageId, version desc)`); barrel update; Drizzle migration `drizzle/0004_*.sql`.
- `packages/crypto/src/`: NEW `buildVaultPageAad` + `canonicalPageAadJson` exported from `browser.ts` only (mirror of credential helper). NEW `deriveTitleSearchKey(masterDek)` + `computeTitleSearchToken(key, title)`. Test vectors under `packages/crypto/test/vault-page-aad.test.ts` + `title-search.test.ts`.
- `packages/shared/src/`: NEW Zod schemas (`PageCreateSchema`, `PageUpdateSchema`, `PageResponseSchema`, `PageHistoryResponseSchema`); NEW error codes (`PAGE_NOT_FOUND`, `PAGE_VERSION_CONFLICT`, `PAGE_BODY_TOO_LARGE`).
- `apps/api/src/`: NEW `pages/` module (controller + service: list/create/get/patch/delete/history). EXTENDED `audit/audit-event.ts` (`page.{create,update,delete,view}`). EXTENDED `common/throttler.config.ts` (`page-write-user` 60/min/user).
- `apps/web/src/`: NEW `app/(authed)/pages/page.tsx` (list + title-prefix search bar), `app/(authed)/page/new/page.tsx`, `app/(authed)/page/[id]/page.tsx` (editor + version-history side panel). NEW `lib/api/pages-client.ts`. NEW `lib/crypto/page-cipher.ts` (encrypt/decrypt + AAD build + token compute). NEW `lib/tiptap/schema.ts` (strict node/mark schema), `lib/tiptap/editor.tsx` (TipTap React wrapper), `lib/tiptap/sanitize.ts` (defensive `sanitize-html` config + render helper for history view).
- `cypress/e2e/`: NEW `pages-crud.cy.ts` (create → list → search by title prefix → edit → history rotation → delete; CAS conflict → 409; XSS payload via title and link href is neutered).
- `aad-labels.ts` extended with `AAD_LABEL_VAULT_PAGE = "sv:vault-page:v1|"`.

## Key links (where this most likely breaks)

1. **AAD per-page binder MUST include `(vaultId ‖ pageId ‖ version)`.** Same three-axis attack surface as credentials: omit `vaultId` → cross-vault substitution; omit `pageId` → cross-page swap; omit `version` → rollback (matters MORE for pages because `page_versions` retains 10 prior ciphertexts the server could replay against the live `:id`). The v-suffix bump is a data-migration event. `buildVaultPageAad` and `buildVaultCredentialAad` MUST stay structurally identical (parity test enforces).
2. **TipTap schema validation is CLIENT-ONLY.** The server cannot peek into the ciphertext. REQ-VAULT-008 schema strictness lives in `lib/tiptap/schema.ts` and the editor's `parseOptions`. Server-side input-validation auditor will look for "TipTap JSON validation on submit"; the answer is "the document is encrypted; server validates the envelope only." Document this in INDEX (here), in `pages.controller.ts` JSDoc, and in `RUNBOOK.md`. Anyone who later adds server-side TipTap parsing has reintroduced the keyhole the encryption was designed to close.
3. **Title-search token leaks ~32 bits per title.** 8-byte prefix means an attacker with DB read can bucket pages by title-equality up to ~2³² collision space; lowercased + HMAC-keyed, so they can't recover the title, only group it. Acceptable per REQ-VAULT-010 and ≤50-user scale. Choosing 4 bytes would leak less but cause prefix collisions on common titles ("Notes", "Todo"); 16 bytes leaks more. Decision frozen at 8.
4. **`title_search_key` is NOT `master_DEK`.** Derived via `HKDF-Expand(master_DEK, "sv:title-search:v1", 32)`. Using `master_DEK` directly for HMAC would expose it to a known-plaintext oracle (server controls the title via search query). HKDF info string is FROZEN; bumping it invalidates every existing token and forces a client-side re-index pass.
5. **History rotation MUST be atomic with the PATCH.** `INSERT INTO page_versions (...PRE-update row...); UPDATE pages SET ... WHERE version=$current; DELETE FROM page_versions WHERE page_id=$id AND version NOT IN (SELECT version FROM page_versions WHERE page_id=$id ORDER BY version DESC LIMIT 10)` — all in one transaction. Failure mid-flight = either no version-row OR no live update OR uncapped history; transaction wrap is load-bearing.
6. **Defensive `sanitize-html` is belt-AND-suspenders.** TipTap's strict schema rejects bad nodes at parse time, but a malicious `link.href` with `javascript:` could slip through if the schema's URL validator regresses. `sanitize-html` runs at render with an allowlist that mirrors the schema; mismatches fail closed (drop unknown). Configured in `lib/tiptap/sanitize.ts`. (REQ-WEBSEC-005.)
7. **Server cannot do body search.** REQ-VAULT-010: title search server-side, body search client-side after decrypt. INDEX explicitly declines a server-side body-search index. Body search is implemented as a client-side filter over the currently-loaded vault's decrypted page array on `/pages` mount (lazy-decrypts on demand).
8. **Page bodies are larger than credentials.** 64 KiB credential cap is too tight for pages (a long meeting note with 50 paragraphs easily exceeds). Default cap = 256 KiB (env `PAGE_BODY_MAX_BYTES`); ceiling 1 MiB. Above ceiling → 413 `PAGE_BODY_TOO_LARGE`. Also implies CSP/observability sees no change (still all `'self'`).

## Wave map (parallel execution)

```
Wave 1 ──► Plan 01 (DB schema: pages + page_versions + AAD label literal in aad-labels.ts + title-search HKDF helpers + Zod schemas + error codes)
            │
Wave 2 ──┬► Plan 02 (API: pages CRUD + history endpoint + title-prefix search + atomic CAS PATCH + history-rotation tx)             ┐
         ├► Plan 03 (Crypto: buildVaultPageAad + page-cipher + title-search token compute + AAD parity test extension) [TDD]         │ ← parallel
         ├► Plan 04 (TipTap: strict schema + editor component + link sanitization + defensive sanitize-html render helper)           │
         └► Plan 05 (Web: /pages list + /page/new + /page/[id] + history side panel + title-prefix search bar + Cypress smoke)       ┘
```

5 plans, 2 waves. Plan 02 (CAS race + history rotation) and Plan 03 (AAD parity) are `type: tdd`; rest `type: auto`.

## Operator decisions surfaced (REQUIRED before `/gsd:execute-phase 5`)

1. **AAD label literal = `"sv:vault-page:v1|"`.** Apex form, mirrors `sv:vault-credential:v1|`. Frozen. Confirm.
2. **Title-search prefix length = 8 bytes (~2³² unique buckets).** Tradeoff: shorter leaks less but causes prefix collisions on common titles; longer leaks more. Confirm.
3. **Title-search HKDF info string = `"sv:title-search:v1"`.** Bumping is an index-rebuild event. Confirm.
4. **Page version history depth = 10.** Matches credentials password-history depth. Confirm.
5. **Default page mode = single-locked (`is_locked=false`).** Phase 06 (deferred) adds double-lock; column is forward-compat. Confirm.
6. **Body search scope = client-side, currently-loaded vault only (per REQ-VAULT-010).** No server-side body-search index. Confirm.

## Phase 05 complete when

1. All 5 plans show ✅ in `STATE.md`.
2. All 14 goal-backward truths verified in `05-VERIFICATION.md`.
3. AAD parity test (`aad-parity.test.ts`) green and asserts `"sv:vault-page:v1|"` lives only in `aad-labels.ts`.
4. Cypress `pages-crud.cy.ts` green: create, search by prefix, edit (version bumps + history rotates at >10), delete, CAS conflict 409, link `javascript:` href is stripped.

(MVP track: 4-auditor security gate is deferred to MVP-Phase-Z consolidated pass.)
