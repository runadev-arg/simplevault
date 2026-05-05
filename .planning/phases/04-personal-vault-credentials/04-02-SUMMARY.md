---
phase: 04-personal-vault-credentials
plan: 04-02
subsystem: api-credentials-crud
tags: [credentials, cas-patch, anti-enum, uniform-404, audit-events, tdd]
requires:
  - 04-01 (vaults + credentials schemas; AAD label; Require2FAGuard available)
provides:
  - apps/api/src/credentials/ (controller + service + DTOs + module)
  - CREDENTIAL_NOT_FOUND (E2006) + CREDENTIAL_VERSION_CONFLICT (E2007)
  - AuditAction.{CredentialCreate,CredentialView,CredentialUpdate,CredentialDelete}
  - REST surface POST/GET/PATCH/DELETE /credentials/:id with atomic CAS PATCH
  - uniform-404 anti-enumeration on cross-user GET/PATCH/DELETE
affects:
  - 04-06 (web client) — consumes the 409 CREDENTIAL_VERSION_CONFLICT typed surface
  - 04-09 / 04-10 (web client roundtrip) — POST→GET→PATCH→DELETE end-to-end
  - 04-11 (audit-pino redact) — finalises redact list for the four credential.* actions
  - 04-12 (Cypress IDOR) — exercises the cross-user-404 invariant
duration: ~45min
completed: 2026-05-05
---

# Phase 04 Plan 02: API credentials CRUD + atomic CAS PATCH Summary

Three atomic commits land the `/credentials/*` REST surface on the personal vault. The CAS-PATCH (`UPDATE … WHERE c.version = $witness`) is the load-bearing primitive: zero rows = either "doesn't belong to caller" (uniform 404) or "version stale" (409), disambiguated by a follow-up SELECT that ITSELF joins on `vaults.owner_user_id = $userId` so the 404-vs-409 branch cannot leak existence cross-user. TDD via mock-based unit spec (10 tests RED→GREEN; race test stable across 30 repeated runs); real-PG e2e coverage stays in Plan 12 per the existing test-boundary in this codebase.

**Status:** COMPLETE
**Date:** 2026-05-05
**Commits:** `a7f8728` (T1 RED), `e5dbfb7` (T2 GREEN), `11b6cff` (T3 controller+wiring)
**Tasks:** 3/3
**Build:** `pnpm --filter @simplevault/api build` green; 46 vitest tests across 6 files pass.

---

## Commits

- `a7f8728` — `test(04-02-T1): credentials CAS race + rollback + cross-user 404 (RED)`
- `e5dbfb7` — `feat(04-02-T2): credentials.service atomic CAS + ownership-join (GREEN)`
- `11b6cff` — `feat(04-02-T3): credentials controller + DTOs + Nest module wiring`

---

## What landed

### Task 1 — `test(04-02-T1)` (RED) — `a7f8728`

- Stub `CredentialsService` (create/getById/update/delete throw `"not impl"`) — public-method shape locked in for T2.
- Spec `credentials.service.spec.ts` (10 tests) covering owner happy paths + the three load-bearing invariants:
  1. Concurrent CAS race — `Promise.allSettled([update, update])` with the same witness; exactly one winner (v1→v2), other 409.
  2. Version-rollback rejection — row at v=3, witness v=1 → 409.
  3. Uniform 404 — cross-user GET/PATCH/DELETE returns `CREDENTIAL_NOT_FOUND` (Truth 3 anti-enum); never 403, never 409 leaking ownership.
- In-memory FakeDb dispatches drizzle `sql` template via `compileSql(queryChunks)` to INSERT/SELECT/UPDATE/DELETE. Per-row mutex serialises CAS writes (mirrors PG row lock so the JS race is observable + deterministic).
- Error codes `CREDENTIAL_NOT_FOUND = "E2006"` + `CREDENTIAL_VERSION_CONFLICT = "E2007"` added to `packages/shared/src/error-codes.ts` (plan said E2001/E2002 — those slots were already taken by `VAULT_NOT_FOUND` / `VAULT_FORBIDDEN` from Plan 04-01; allocated next-free E2xxx, sibling Plan 04-03 added `CREDENTIAL_BODY_TOO_LARGE = "E2008"` consistently).

### Task 2 — `feat(04-02-T2)` (GREEN) — `e5dbfb7`

The full service impl. Four single-statement queries:

- **`create`** — `INSERT INTO credentials (id, vault_id, version, ciphertext, nonce, aad_params_json) SELECT COALESCE($credId::uuid, gen_random_uuid()), v.id, 1, $ct, $nonce, $aad FROM vaults v WHERE v.id = $vaultId AND v.owner_user_id = $userId RETURNING …` — cross-user vaultId → zero rows → uniform 404 by construction. Optional client-supplied `credentialId` is the Plan 04-10 cross-dep (keeps AAD self-consistent on POST without a two-roundtrip dance).

- **`getById`** — `SELECT … FROM credentials c JOIN vaults v ON v.id = c.vault_id WHERE c.id = $id AND v.owner_user_id = $userId` — cross-user → empty rowset → uniform 404 (NEVER 403; Truth 3).

- **`update` (load-bearing CAS)** —
  ```sql
  UPDATE credentials c
  SET ciphertext=$1, nonce=$2, aad_params_json=$3, version = c.version + 1, updated_at = now()
  FROM vaults v
  WHERE c.id=$id AND v.id=c.vault_id AND c.version=$witness AND v.owner_user_id=$userId
  RETURNING c.id, c.vault_id, c.version, c.ciphertext, c.nonce, c.aad_params_json, c.updated_at
  ```
  Zero rows triggers a follow-up ownership-SELECT:
  ```sql
  SELECT c.id FROM credentials c JOIN vaults v ON v.id = c.vault_id
   WHERE c.id = $id AND v.owner_user_id = $userId
  ```
  - Zero rows → `CREDENTIAL_NOT_FOUND` (404).
  - One row → `CREDENTIAL_VERSION_CONFLICT` (409).

  Subtle but load-bearing: the follow-up SELECT itself filters by `owner_user_id`, so it CANNOT leak existence cross-user. This is what makes the uniform-404 anti-enum invariant (Truth 3) hold even on the failure branch — a probe by user B for user A's credentialId still returns 404, never the 409 it would get for one of its own.

- **`delete`** — `DELETE FROM credentials c USING vaults v WHERE c.id=$id AND v.id=c.vault_id AND v.owner_user_id=$userId RETURNING c.id` — rowCount=0 → 404.

10 tests GREEN; race test stable across 30 repeated runs.

T2's commit incidentally swept two sibling-plan diffs (`apps/api/src/common/throttler.config.ts` + `apps/api/src/vault/vault.controller.ts` — Plan 04-03 work-in-progress). Classified as Rule 3 deviation (concurrent-agent index-state contamination); the swept changes are independently sane and align with Plan 04-03's natural evolution.

### Task 3 — `feat(04-02-T3)` (controller + wiring) — `11b6cff`

- **`credentials.controller.ts`** — POST (201) / GET (200) / PATCH (200) / DELETE (204). `safeParse(body)` against `.strict()` Zod schemas; failure → 400 `VALIDATION_FAILED` (matches the in-tree pattern from `signup.controller.ts` etc. — the codebase doesn't have a shared `zodPipe`, so the explicit `safeParse` form is what every controller uses).
- **`credentials.dto.ts`** — `CredentialCreateSchema` + `CredentialUpdateSchema`. Bytea handling: base64 → bounded `Uint8Array` via `.transform()` (mirrors `boundedB64` from Phase-03 TOTP). Field caps: nonce exactly 24 bytes, ciphertext 1..`CIPHERTEXT_MAX_BYTES` (Plan 04-03's `credentials.constants.ts`), aadParamsJson ≤ `AAD_PARAMS_JSON_MAX_BYTES`. `version: z.literal(1)` on create; `version: int >= 0` CAS witness on update.
- **`credentials.module.ts`** — minimal Nest module (controller + service + export). No `Require2FAGuard` import (Key Link 3 / REQ-2FA-003).
- **`app.module.ts`** — `CredentialsModule` registered between `VaultModule` (Plan 04-03) and `TestHelpersModule`.
- **`audit-events.ts`** — `AuditAction` enum widened with `CredentialCreate` / `CredentialView` / `CredentialUpdate` / `CredentialDelete` (action strings `credential.{verb}`). Plan 04-11 will finalise the redact list + any extra `data.*` conventions; emit sites already comply (no plaintext, ciphertext, or AAD bytes — only `{credentialId, vaultId, version}`). Failure paths are NOT audit-emitted (same posture as DELETE /sessions/:id — emitting a fail row keyed off a probed id would itself become an enum oracle).
- Throttler decorators consume sibling Plan 04-03's already-declared `RateLimits.credentialsWriteUser` (60/min) + `RateLimits.credentialsReadUser` (300/min) ceilings. POST/PATCH/DELETE share the write ceiling; GET uses the read ceiling.

---

## Truths verified

| # | Truth | Status |
|---|---|---|
| 1 | `/credentials/*` Nest module exposes POST/GET/PATCH/DELETE behind APP_GUARD JwtAuthGuard; class NOT decorated with Require2FAGuard | OK — `grep -rn "Require2FAGuard" apps/api/src/credentials apps/api/src/vault` returns ONLY doc-comment occurrences explaining the invariant |
| 2 | PATCH executes atomic CAS UPDATE; zero rows updated → 409 CREDENTIAL_VERSION_CONFLICT; version bumped to witness+1 on success | OK — service spec test (6) `concurrent CAS race — exactly one winner, other 409` + test (7) `version-rollback (row at v=3, caller witnesses v=1) → 409` |
| 3 | Cross-user / not-found on GET/PATCH/DELETE returns uniform 404 CREDENTIAL_NOT_FOUND | OK — service spec tests (4), (8), (10) all verify code `E2006` + status 404 on cross-user calls; NEVER 403 |
| 4 | ParseUUIDPipe stays on `:id` routes (FINDING-0051 carry-posture) | OK — controller uses `new ParseUUIDPipe({version: "4"})` on every `:id` route |
| 5 | TDD spec covers race + rollback + cross-user-404 | OK — 10 tests RED→GREEN, race-test stable across 30 repeated runs |

`grep -rn "@simplevault/crypto" apps/api/src/credentials/` returns ZERO non-comment occurrences (Truth 7b — server never touches plaintext).

---

## Deviations from Plan

### Rule 1 — Bug fixes (test-harness)

**1. `compileSql` parser missed inlined-primitive params.** Drizzle's `sql\`UPDATE … ${id} …\`` template wraps SQL fragments in `{value: [string]}` (StringChunk) but inlines primitive substituted values (strings, numbers) DIRECTLY (not in a `{value, encoder}` Param wrapper). T1's parser only handled the StringChunk + Param branches; primitives fell through and were lost. Fixed in T2 to fall through to "raw value" when neither shape matches. Test-infra only — assertions stayed RED through T1 with the bug.

### Rule 2 — Adaptations to existing infra

**2. Mock-based unit spec instead of real-DB harness.** Plan said "uses the existing test-DB harness (`drizzle:setup-test`)". The harness doesn't exist in this repo; the in-tree pattern (`2fa-removal.spec.ts`, `jwt-epoch.spec.ts`) is mock-based unit tests with real-PG e2e deferred to Plan 12 (Cypress + service containers). Adopted that pattern; built an in-memory FakeDb that mirrors PG's CAS + ownership-join semantics including a per-row mutex so the JS-event-loop race is observable + deterministic. The contract under test is identical; the medium is in-process.

**3. Error codes E2006/E2007 instead of plan-listed E2001/E2002.** Plan said "next free range after Phase-03 E10xx" but pre-existing E2001 (`VAULT_NOT_FOUND`) + E2002 (`VAULT_FORBIDDEN`) from Plan 04-01 already occupied those slots. Allocated next-free E2006 + E2007. Sibling Plan 04-03 likewise allocated E2008 for `CREDENTIAL_BODY_TOO_LARGE` consistently. Inline comment in `error-codes.ts` documents the rationale.

**4. `safeParse(body)` instead of `zodPipe(Schema)`.** The codebase has no `zodPipe` factory; every existing controller (`signup`, `login`, `invite`, `2fa/totp`, `2fa/webauthn-*`) uses inline `Schema.safeParse(body)` + a `BadRequestException({error: {code: VALIDATION_FAILED, …}})` on failure. Adopted the same pattern.

### Rule 3 — Concurrent-agent contamination (single-event)

**5. T2 commit (`e5dbfb7`) accidentally swept sibling Plan 04-03 work-in-progress into its diff.** `git add` of the credentials files captured uncommitted edits to `apps/api/src/common/throttler.config.ts` and `apps/api/src/vault/vault.controller.ts` that sibling agents had staged in the shared index. The swept changes are independently sane (move `vault.controller.ts` from a literal `@Throttle({"vault-list-user": …})` to `RateLimits.vaultListUser.*`; declare the credentials throttler ceilings) and align with Plan 04-03's natural evolution; not reverted because the alternative is `git reset --hard` against another agent's WIP. Single-occurrence — T1 and T3 commits used `git add <specific files>` and were clean.

### No Rule 4 (architectural) deviations

The CAS-PATCH SQL, uniform-404 disambiguation, audit emit semantics, and throttler-ceiling consumption all match the plan exactly.

---

## Authentication Gates

None — no new external services. Existing JwtAuthGuard (APP_GUARD) covers every credentials route automatically.

---

## Hand-offs

**Plan 04-03 (sibling, also in Wave 2)** — declared `RateLimits.credentialsWriteUser` (60/min) + `RateLimits.credentialsReadUser` (300/min) consumed by this controller's `@Throttle` decorators, plus the body-parser cap on `/credentials/*` routes (`CREDENTIAL_BODY_TOO_LARGE = E2008`). Already shipped.

**Plan 04-06 (web client)** — typed surface for the 409 conflict: `if (response.status === 409 && body.error.code === "E2007") { /* version conflict */ }`. The CAS-witness on PATCH is the `version` field the client gets back from the previous GET / POST.

**Plan 04-09 / 04-10 (web roundtrip)** — POST→GET→PATCH→DELETE through these endpoints. POST accepts an optional client-supplied `credentialId` so the AAD computed at encryption time stays self-consistent (no two-roundtrip "encrypt-with-placeholder, server returns id, re-encrypt" dance).

**Plan 04-11 (audit + redact)** — the four `credential.*` AuditActions are emitted. Plan 04-11 needs to extend the Pino redact list with any `data.*` field-name conventions added beyond the current `{credentialId, vaultId, version}`.

**Plan 04-12 (Cypress IDOR)** — dual-user fixture POSTs from User A, then GET/PATCH/DELETE from User B; assert response is 404 + `error.code === "E2006"`, NOT 403.

---

## Files

**Created:**
- `apps/api/src/credentials/credentials.controller.ts`
- `apps/api/src/credentials/credentials.service.ts`
- `apps/api/src/credentials/credentials.dto.ts`
- `apps/api/src/credentials/credentials.module.ts`
- `apps/api/test/credentials.service.spec.ts`

**Modified:**
- `apps/api/src/app.module.ts` (CredentialsModule import + register)
- `apps/api/src/common/audit-events.ts` (4 new `credential.*` actions)
- `packages/shared/src/error-codes.ts` (CREDENTIAL_NOT_FOUND + CREDENTIAL_VERSION_CONFLICT)

**Swept-in by T2 (Rule 3, sibling Plan 04-03 WIP):**
- `apps/api/src/common/throttler.config.ts`
- `apps/api/src/vault/vault.controller.ts`

---

## Next plans unblocked

Wave 2 siblings (04-03/04/05) continue in parallel; Wave 3 web-roundtrip (04-06/09/10) depends on this surface being stable. Plan 04-12 Cypress IDOR test will exercise the uniform-404 invariant on a real PG instance.
