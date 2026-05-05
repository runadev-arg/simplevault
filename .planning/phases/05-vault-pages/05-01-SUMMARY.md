---
phase: 05-vault-pages
plan: 01
subsystem: db-schema + aad-label + crypto-stubs + zod
tags: [drizzle, postgres, pages, page_versions, aad-label, hkdf, title-search, zod]
requires:
  - 04-01 (vaults table FK target + AAD-label module pattern)
  - 04-04 (vault-credential AAD builder = sibling-parity template)
provides:
  - pages table (id, vault_id FK cascade, version, ciphertext, nonce, aad_params_json, title_search_token, is_locked, timestamps; indexes on vault_id + title_search_token)
  - page_versions table (id, page_id FK cascade, version, ciphertext, nonce, aad_params_json, created_at; index on (page_id, version DESC))
  - 0004_phase05_pages_and_versions.sql (manually renamed from drizzle-kit auto-tag)
  - AAD_LABEL_VAULT_PAGE = "sv:vault-page:v1|" + TITLE_SEARCH_HKDF_INFO = "sv:title-search:v1" frozen constants + byte-asserted vitest
  - vault-page.ts in @simplevault/crypto: buildVaultPageAad / canonicalPageAadJson / deriveTitleSearchKey / computeTitleSearchToken (NotImplementedError stubs)
  - PageCreateSchema / PageUpdateSchema / PageResponseSchema / PageHistoryResponseSchema in @simplevault/shared
  - Error codes PAGE_NOT_FOUND=E2009, PAGE_VERSION_CONFLICT=E2010, PAGE_BODY_TOO_LARGE=E2011
affects:
  - 05-02 (pages.controller + pages.service consume the schemas + DTOs)
  - 05-03 (full impl + parity tests for the 4 vault-page crypto helpers)
  - 05-04 (PATCH transaction enforces 10-snapshot rotation in page_versions)
  - 05-05 (web client + Markdown editor consume PageResponse / PageHistoryResponse)
key-decisions:
  - title_search_token is bytea (no DB-level length cap); 8-byte length enforced at the Zod boundary — same pattern as nonce.
  - is_locked is a Phase-06 forward-compat hook landed now so the Phase-06 migration is a no-op DDL change.
  - Page Zod schemas live in @simplevault/shared (NOT apps/api) because Wave 2 has the web client construct + validate the same shapes for optimistic round-trips.
  - Crypto helper stubs throw NotImplementedError so 05-02..05-05 can import the type signatures; full impl + parity tests deliberately deferred to Plan 05-03.
  - Error codes allocated next-free in E2xxx (E2009..E2011), matching the same Rule-2 adaptation note as the credentials triplet (E2006..E2008).
commits:
  - 9be8c9d feat(05-01-T1): pages + page_versions Drizzle schemas + 0004 migration
  - 7eecfc2 feat(05-01-T2): AAD_LABEL_VAULT_PAGE + title-search HKDF info + crypto stubs
  - ea0fbc8 feat(05-01-T3): page Zod schemas + PAGE_NOT_FOUND/CONFLICT/TOO_LARGE codes
verify:
  - "pnpm --filter @simplevault/db build: PASS"
  - "pnpm --filter @simplevault/api build: PASS"
  - "pnpm --filter @simplevault/crypto test: 98/98 PASS (10 files)"
  - "pnpm --filter @simplevault/web vitest run aad-labels: 1/1 PASS"
  - "pnpm -w typecheck: 8/9 packages PASS — apps/web typecheck failures are PRE-EXISTING (credentials-client.test.ts unused-import + credential-cipher.test.ts possibly-undefined; both unrelated to 05-01)"
  - "pnpm -w lint: pre-existing pgTable-deprecated lint errors across ALL schema files (Drizzle 0.45 API drift); new pages.ts + page_versions.ts mirror the existing pattern (Rule-2 consistency). No regression."
duration: ~30min
completed: 2026-05-04
---

# Phase 05 Plan 01: pages + page_versions schema, AAD label, title-search HKDF stubs, page Zod

Wave 1 / 5-plan MVP-track foundation. Three atomic commits land the structural skeleton everyone in Wave 2 imports: two Postgres tables (with the Phase-06 `is_locked` forward-compat hook and the 8-byte title-search index baked in), one new FROZEN AAD-label constant + the title-search HKDF info string, four browser-only crypto helper stubs (full impl deferred to Plan 05-03), and the page request/response Zod schemas in `@simplevault/shared` so the web client can round-trip the same shapes the API validates.

**Status:** COMPLETE
**Date:** 2026-05-04

## Hand-offs to Wave 2

- **05-02 (pages CRUD controller/service):** `import { PageCreateSchema, PageUpdateSchema } from "@simplevault/shared"` for the body validation; `import { pages, pageVersions } from "@simplevault/db/schema"` for the queries; the 10-snapshot rotation lives in the PATCH transaction (Plan 05-04).
- **05-03 (vault-page crypto helpers — full impl + TDD):** replace the four `NotImplementedError` stubs in `packages/crypto/src/vault-page.ts`; land the `apps/web` aad-parity test asserting `buildVaultPageAad` imports `AAD_LABEL_VAULT_PAGE` (never re-declares the literal); land the title-normalisation policy spec.
- **05-04 (PATCH + history rotation):** `PAGE_VERSION_CONFLICT` (E2010) is the CAS-witness 409; `PAGE_BODY_TOO_LARGE` (E2011) is the body-parser 413 mapping; trim `page_versions` to last-10 inside the PATCH transaction.
- **05-05 (web Markdown editor + history viewer):** `PageResponseSchema` / `PageHistoryResponseSchema` are the strict-allowlist response shapes — `.parse(...)` server-side as defence-in-depth (Truth 9 sibling).
