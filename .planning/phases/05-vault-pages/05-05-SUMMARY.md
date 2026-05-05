# Plan 05-05 — SUMMARY

Phase 05 Wave 2 / MVP-track. Web routes + Cypress smoke for the pages
surface.

## Commits

- `feat(05-05-T1)` — `apps/web/src/lib/api/pages-client.ts`: typed
  wrappers (`listPages`, `searchPagesByTitlePrefix`, `createPage`,
  `getPage`, `patchPage` aka `updatePage`, `deletePage`,
  `getPageHistory`) + `PageVersionConflictError` (E2010, 409),
  `PageNotFoundError` (E2009, 404), `PageBodyTooLargeError` (E2011, 413).
  Wire shape: ciphertext / nonce / titleSearchToken as base64url on the
  wire, `Uint8Array` in JS. Goes through the shared Phase-02 `request`
  helper (no duplicate fetch logic).
- `feat(05-05-T2)` — three authed routes:
  - `/pages` — debounced (200ms) title-prefix search bar (client computes
    8-byte HMAC token via `computeTitleSearchToken`, hex-encodes, fires
    `?q=`); body-search toggle filters client-side over decrypted
    title+body (REQ-VAULT-010); favourites pinned + `updatedAt desc`
    secondary sort; eager-decrypt all pages (≤50-user scale fine);
    Aceternity card grid; empty-state CTA.
  - `/page/new` — title input + `<PageEditor>`; client-chosen UUIDv4
    (AAD self-consistency); `encryptPage` → `createPage` →
    `router.replace("/page/[id]")`.
  - `/page/[id]` — live editor + favourite toggle + delete; collapsible
    version-history side panel (lazy: history list on open, per-version
    decrypt only on Preview/Restore click — never eager); CAS PATCH with
    witness `version`; on `PageVersionConflictError` surface a typed
    "page changed in another tab" modal with reload-or-cancel (NEVER
    silent).
- `test(05-05-T3)` — `apps/web/cypress/e2e/pages-crud.cy.ts`: empty CTA →
  create → server prefix-search → client body-search → edit (v2) →
  10-edit history rotation cap → XSS paste neutered → `javascript:` link
  rejected → delete → empty.

## /pages First Load JS

NOT MEASURED in this plan: `pnpm --filter @simplevault/web build` fails
because Wave-2 siblings 05-03 (`apps/web/src/lib/crypto/page-cipher.ts`,
crypto pkg `encryptPage`/`decryptPage`/`extractTitle`/
`deriveTitleSearchKey`/`computeTitleSearchToken` impls) and 05-04 (the
internal `./schema` import in `tiptap-editor/index.tsx`) have not yet
landed at the time this plan ran. End-of-wave verification will measure
once the siblings are green; the page bundle composition (TipTap +
sanitize-html + Aceternity card grid + page-cipher) is expected to
introduce ~50-80 KiB over the credentials list page baseline due to
TipTap's parser, which is acceptable given the dynamic-import budget
(REQ-WEBSEC-005 / Phase 04 SUMMARY-09 budget tooling will catch
regressions).

## Deviations / unresolved-imports (expected at end-of-wave)

1. `apps/web/src/lib/crypto/page-cipher` — owned by 05-03; imported by
   all three new routes. Not stubbed per plan instructions (no fallback
   stubs in sibling files).
2. `@simplevault/crypto/browser` exports `deriveTitleSearchKey`,
   `computeTitleSearchToken` — currently stubs throwing
   `NotImplementedError`; 05-03 lands the impl.
3. `apps/web/src/components/tiptap-editor/index.tsx` imports `./schema`
   which 05-04 will rename/produce as `./extensions.ts` (or similar).
   The `<PageEditor>` and `<RenderedTipTapHtml>` exports are already
   present in the sibling tree.
4. `<PageEditor>` is currently typed as accepting `value: JSONContent`
   in 05-04; this plan passes a `{ type: "doc" }` shape and casts at the
   boundary. Either side may tighten once 05-04 ships.
5. The Cypress spec's two-tab CAS-conflict exercise is a stub assertion
   pending a deterministic two-tab harness; the typed
   `PageVersionConflictError` modal path is fully wired in `[id]/page.tsx`
   and unit-testable directly.
6. The `/pages?q=<hex>` server contract (Plan 05-02) advertises a
   metadata-only listing including `titleSearchToken`. The wire schema
   is encoded that way in `pages-client.ts`; if 05-02 lands a
   different field (e.g. omits `titleSearchToken` from the list to
   reduce leakage) the client schema needs a one-line edit.
