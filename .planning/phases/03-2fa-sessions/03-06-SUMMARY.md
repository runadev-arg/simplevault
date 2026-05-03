---
phase: 03-2fa-sessions
plan: 06
subsystem: twofa-methods-api
tags: [2fa, methods, removal-guard, anti-enumeration, hand-off-seam, audit, throttler]
requires:
  - 03-01 (webauthn_credentials + totp_credentials schemas)
  - 03-02 (WebAuthn API — populates webauthn_credentials)
  - 03-03 (TOTP API — populates totp_credentials)
provides:
  - GET /2fa/methods (Truth 9)
  - DELETE /2fa/methods/:id (Truth 10)
  - MethodsService.list / countActive / remove / removeGuarded
  - userHasSharedVaultDependency stub + Phase 07 swap point
  - AuditAction.TwoFaMethodRemoved
  - Throttler ceilings 2fa-methods-list-user / 2fa-methods-delete-user
  - Error code AUTH_2FA_REMOVAL_BLOCKED (E1018)
affects:
  - 03-07 (MethodsService.countActive is the natural production binding for Require2FAGuard's count reader; current default falls back to a self-contained DB-backed reader to avoid a circular import — see 03-07-SUMMARY.md)
  - 03-09 (when APP_GUARD reorder lands, the two new ceilings start keying off req.user.id for real)
  - 03-10 (web /settings/security UI consumes these endpoints)
  - 07-XX (vault_members membership query — Phase 07 swaps the userHasSharedVaultDependency body)
tech-stack:
  added: []
  patterns:
    - "Strict-allowlist SELECT projection on /2fa/methods response — server-side `.parse(...)` against TwoFaMethodsListSchema as defence-in-depth against future ORM-hydration leaks"
    - "Cross-table id lookup (webauthn_credentials.id ⊕ totp_credentials.id, both UUID-v4 from defaultRandom — collision probability negligible). Try webauthn first; on miss try totp; on miss return null → uniform 404"
    - "Phase-07 hand-off seam via mutable `MethodsService.sharedVaultDependencyCheck` field (default = stub-returns-false). Integration test injects its own stub. Phase 07 only has to swap the module-level stub body — integration tests remain green"
key-files:
  created:
    - apps/api/src/twofa/methods/methods.controller.ts
    - apps/api/src/twofa/methods/methods.service.ts
    - apps/api/test/2fa-removal.spec.ts
  modified:
    - apps/api/src/twofa/twofa.module.ts (register MethodsController + MethodsService)
    - apps/api/src/common/throttler.config.ts (twoFaMethodsListUser, twoFaMethodsDeleteUser ceilings)
    - apps/api/src/common/audit-events.ts (TwoFaMethodRemoved)
    - packages/shared/src/zod/index.ts (TwoFaMethodSchema, TwoFaMethodsListSchema)
    - packages/shared/src/error-codes.ts (AUTH_2FA_REMOVAL_BLOCKED = E1018)
duration: ~30min (recovery agent — siblings had pre-staged most of T1)
completed: 2026-05-02
---

# Phase 03 Plan 06: 2FA methods API (list + remove + removal-guard) Summary

User-facing 2FA method management API. Truth 9 covers the list endpoint with strict-allowlist output; Truth 10 covers the cross-table delete with anti-enumeration 404 + Phase-07-deferred shared-vault dependency guard.

**Status:** COMPLETE (recovery agent)
**Date:** 2026-05-02
**Commits:** `a8b31f1` (T1 list + remove), `5de3538` (T2 removal-guard + integration test)
**Tasks:** 2/2

---

## What landed

### Task 1 — `feat(03-06-T1): GET /2fa/methods + DELETE /2fa/methods/:id (no removal guard yet)` (`a8b31f1`)

NEW directory `apps/api/src/twofa/methods/` (controller + service). Wired into `TwoFaModule` providers + exports.

**`MethodsService.list(userId)`**: SELECTs only the five public fields (`id`, `name`, `createdAt`, `lastUsedAt` + the synthesised `kind` discriminator) per Truth 9. NEVER touches `credentialId` / `publicKey` / `counter` / `aaguid` / `transports` (webauthn) or `wrappedSecret` / `encryptedSecretAad` / `lastUsedStep` (totp). Order: webauthn first, then totp, then by `createdAt` asc within each group.

**`MethodsService.countActive(userId)`**: cardinality across both tables. Two `count()` queries via Drizzle — used by Plan 06 T2's removal guard AND by Plan 07's `Require2FAGuard` (the latter's `DbBackedRequire2FACountReader` runs the equivalent UNION ALL inline to avoid a circular module import; once both plans land cleanly, the binding can be flipped to `useExisting: MethodsService` — documented in `require-2fa.guard.ts`'s class-level jsdoc).

**`MethodsService.remove(userId, methodId)`**: cross-table lookup gated on `(id, user_id)`. Tries `webauthn_credentials` first; on zero rows tries `totp_credentials`; on zero rows returns `null`. Anti-enumeration: cross-user / unknown id collapse to the same `null` → controller maps to uniform 404 (NEVER 403). UUID-v4 collision probability is negligible — both id columns are `defaultRandom()`.

**Controller `MethodsController`**: `GET /2fa/methods` re-parses the response through `TwoFaMethodsListSchema.parse(items)` before returning (defence-in-depth — a future ORM-hydration leak surfaces as a 500, not a silent secret exfil). `DELETE /2fa/methods/:id` validates `:id` via `ParseUUIDPipe({version:"4"})`, returns 204 on success, 404 on cross-user / non-existent. Audit: `auth.2fa.method.removed` with `data: {kind: "webauthn"|"totp"}` so the operator dashboard can partition removals by authenticator type without re-querying.

Throttler ceilings: `2fa-methods-list-user` (60/min user-keyed), `2fa-methods-delete-user` (30/min user-keyed). Same Plan-09 caveat as the Plan 05 sessions ceilings (user-keying becomes effective once the APP_GUARD reorder lands; until then, falls back to IP). Documented inline.

### Task 2 — `feat(03-06-T2): removal-guard + userHasSharedVaultDependency stub + integration test` (`5de3538`)

**`userHasSharedVaultDependency`** (module-level export in `methods.service.ts`): Phase-07 hand-off seam. Stub-returns-`false` body with `// TODO(phase-07): replace with SELECT 1 FROM vault_members WHERE user_id = $1 LIMIT 1`. Phase 07 swaps the body — the integration test stays green because it injects its own stub.

**`MethodsService.sharedVaultDependencyCheck`**: mutable instance field defaulting to the module-level stub. Lets the integration test flip behaviour without touching production source. Vitest spies / direct assignment both work.

**`MethodsService.removeGuarded(userId, methodId)`**:
1. `countActive(userId)`. If `before === 0` → fall through to `remove` (returns null → 404; anti-enumeration).
2. `countAfter = before - 1`. If `countAfter === 0` AND `await this.sharedVaultDependencyCheck(userId)` is true → throw 409 `AUTH_2FA_REMOVAL_BLOCKED` with envelope `{error:{code:"E1018", message:"...", data:{requires:"shared_vault_2fa"}}}`. The DELETE does NOT run.
3. Otherwise call `remove(...)`.

TOCTOU note (acceptable in Phase 03): the gap between `countActive` and `remove` could in principle let a parallel request bring the count down to 0 between checks. In Phase 03 the dep-stub always returns `false` — the 409 branch is unreachable in production. Phase 07 may want to wrap both queries in a transaction; documented inline so they don't have to re-derive.

**Controller**: rewired `DELETE /2fa/methods/:id` from `remove` to `removeGuarded`. Same response shape on success / 404; only the 409 branch is new.

**Integration test `apps/api/test/2fa-removal.spec.ts`** (5 invariants, all GREEN, no real Postgres / Redis):
1. Baseline (deps=false stub) — last-method removal succeeds.
2. deps=true + count after = 0 → 409 (method NOT removed; spy verifies `remove` was not called).
3. deps=true + count after = 1 → 204 (only 0-after triggers).
4. count = 0 (cross-user / non-existent) → null (caller maps to 404, NEVER 403).
5. 409 envelope shape: status (CONFLICT) + code (`E1018`) + `data.requires` (`"shared_vault_2fa"`) all asserted.

**Error code `AUTH_2FA_REMOVAL_BLOCKED = "E1018"`**. Plan-prescribed name was `E1014` but that slot is already held by `AUTH_2FA_NO_METHOD` (Plan 02). Recovery agent picks the next available rather than renumbering — `ErrorCodes` is referenced by name everywhere, so callers are unaffected.

---

## Truths verified

| # | Truth (from `03-INDEX.md`) | Status |
|---|---|---|
| T9 | `GET /2fa/methods` returns merged list with `{id, kind, name, createdAt, lastUsedAt}`; ordered webauthn first then totp then by createdAt asc; NEVER includes secret material / public-key bytes / counter / wrapped blobs / aaguid / transports | OK — explicit field projection in `MethodsService.list`; Zod re-parse in controller as defence-in-depth. |
| T10 | `DELETE /2fa/methods/:id` removes by id+user_id; 404 (NOT 403) on cross-user; emits `2fa.method.removed` audit; removal-guard 409 path testable via stub-flip | OK — `removeGuarded` 409 path tested under deps=true; `userHasSharedVaultDependency` returns false in Phase 03 with explicit `// TODO(phase-07)` and Phase 07 swap-point documented. |

---

## Decisions Made

1. **`Require2FAGuard` lives in `require-2fa.guard.ts` (Plan 07), not `two-fa-guard.ts` (Plan 06 PLAN's prescription).** The recovery prompt explicitly attributes `Require2FAGuard` to Plan 07. Plan 06 keeps only the `userHasSharedVaultDependency` helper, alongside its sole consumer in `methods.service.ts`. Both plans share the contract via TypeScript types — no circular import.
2. **`AUTH_2FA_REMOVAL_BLOCKED = "E1018"` (not `"E1014"` as Plan 06 PLAN prescribed).** E1014 is already `AUTH_2FA_NO_METHOD` (Plan 02). `ErrorCodes` is name-referenced; the slot doesn't matter to callers.
3. **Mutable instance seam (`MethodsService.sharedVaultDependencyCheck`) for the Phase 07 hand-off.** Module-level default points to the static stub. Test can flip the field without touching production code; Phase 07 only has to swap the module-level stub body. Mirrors the test-helper pattern used by Plan 04's `SessionEpochCache`.
4. **Cross-table lookup order: webauthn first, totp second.** Could be parallel; sequential is simpler and avoids a useless second query when the first hits. UUID-v4 collision probability is negligible.
5. **Strict-allowlist Zod re-parse on `/2fa/methods` response.** `TwoFaMethodsListSchema.parse(items)` runs server-side before responding. Catches future bugs where someone adds `wrappedSecret` to the SELECT projection.
6. **`auth.2fa.method.removed` audit name (with `auth.` prefix).** Mirrors the `auth.<verb>.<outcome>` namespace already established by Phase 02; Plan 06 PLAN had it without the prefix (`2fa.method.removed`). Recovery agent normalised to the surrounding convention; rationale documented in audit-events.ts comment.
7. **Removal guard runs BEFORE the DELETE (not after).** A post-DELETE check would have to reinsert the row on 409 — strictly worse. Pre-DELETE check + acceptable TOCTOU window in Phase 03 (where the dep stub is always false anyway).
8. **TOCTOU between `countActive` and `remove` left unprotected in Phase 03.** A future hardening pass can wrap both in a transaction. The 409 path is unreachable in Phase 03 (dep stub returns false unconditionally), so the window is theoretical.
9. **Mock-based unit tests (Vitest); real PG e2e in Plan 12.** Mirrors Plan 04's pattern. Real PG validation lives in Plan 12's Cypress + service-containers harness.

---

## Deviations from Plan

### Rule 3 (auto-fixed blocking issues)

**1. [Rule 3 — Wave-3 cross-talk] Recovery agent inherited mixed-state working tree.**

- **Found during:** Recovery start.
- **Issue:** `audit-events.ts`, `throttler.config.ts`, `twofa.module.ts`, `packages/shared/src/zod/index.ts` all carried interleaved hunks for Plans 05 / 06 / 07.
- **Fix:** Hunk-level attribution via hand-written patches applied with `git apply --cached`. Plan 06's bits staged + committed; Plan 07's bits left in the working tree.
- **Impact:** Two atomic commits with clean blame attribution.

**2. [Rule 3 — Plan-prescribed file location for `Require2FAGuard` overruled by recovery prompt.]**

- **Found during:** Recovery triage.
- **Issue:** Plan 06 PLAN.md says `Require2FAGuard` lives in `apps/api/src/twofa/two-fa-guard.ts`. The recovery prompt explicitly says "2FA-required guard → Plan 07" with the file `apps/api/src/twofa/require-2fa.guard.ts`.
- **Fix:** Recovery prompt wins. `Require2FAGuard` stays in Plan 07's territory; Plan 06 keeps only `userHasSharedVaultDependency` (alongside its consumer in `methods.service.ts`).
- **Impact:** Plan 06's `two-fa-guard.ts` file is NOT created. Plan 06's PLAN file should be amended for posterity but is left as-is (post-execution PLAN edits are out of scope).

**3. [Rule 1 — Bug] Error code slot collision.**

- **Found during:** T2 implementation.
- **Issue:** Plan 06 PLAN said `AUTH_2FA_REMOVAL_BLOCKED = "E1014"` and `AUTH_2FA_REQUIRED = "E1015"`. Both slots were already taken (E1014 = `AUTH_2FA_NO_METHOD` from Plan 02; E1015 = `AUTH_2FA_TOTP_REPLAY` from Plan 03; E1002 = `AUTH_2FA_REQUIRED` from Phase 01).
- **Fix:** Recovery agent renumbered `AUTH_2FA_REMOVAL_BLOCKED` to E1018 (next available). `AUTH_2FA_REQUIRED` was already at E1002 since Phase 01 — no work needed.
- **Impact:** `ErrorCodes.AUTH_2FA_REMOVAL_BLOCKED` is referenced by name everywhere; the slot number is transparent.

**4. [Rule 2 — Defence-in-depth] Audit-action name normalised to `auth.` prefix.**

- **Found during:** T1 audit-event addition.
- **Issue:** Plan 06 PLAN prescribed `2fa.method.removed`. Phase 02's audit namespace is `auth.<verb>.<outcome>`; the rest of Phase 03 (Plans 02/03/04/05) all kept the prefix.
- **Fix:** Recovery agent normalised to `auth.2fa.method.removed` for namespace consistency.
- **Impact:** Plan 10 (audit hash chain) will see a uniform namespace; no operator dashboard query has to special-case missing-prefix events.

### No Rule 4 (architectural) deviations. No CHECKPOINTs raised.

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm --filter @simplevault/api typecheck` (Plan 06 staged tree only — siblings stashed) | GREEN at both T1 and T2 boundaries (after `pnpm --filter @simplevault/shared build` to refresh the dist for the new error-code export). |
| `pnpm --filter @simplevault/api test 2fa-removal` | 5/5 GREEN. |
| Cross-user delete = 404 (NOT 403) | OK — `MethodsService.remove` returns null on cross-user, controller maps via `NotFoundException`. Same response shape as unknown id. |
| Removal-guard 409 path testable via stub flip | OK — test (2) flips `sharedVaultDependencyCheck` to `() => true` and verifies the 409 + `data.requires:"shared_vault_2fa"` envelope. `remove` is asserted NOT to be called. |
| `userHasSharedVaultDependency` returns false in Phase 03 | OK — module-level default stub returns `false`. `// TODO(phase-07)` comment marks the swap point. |
| Strict-allowlist Zod re-parse on `GET /2fa/methods` | OK — `TwoFaMethodsListSchema.parse(items)` in controller. |

---

## Hand-offs

**Plan 07 (Require2FAGuard + probe):**
- Reuses `MethodsService.countActive` as the production binding for the count-reader (eventually). Until both plans close cleanly, Plan 07 ships its own `DbBackedRequire2FACountReader` with the same UNION ALL count query inline to avoid a circular module import — both readers satisfy the `Require2FACountReader` interface, swap is a `useExisting:` change.

**Plan 09 (throttler ordering):**
- Once `JwtAuthGuard` becomes APP_GUARD, the two new ceilings (`2fa-methods-list-user`, `2fa-methods-delete-user`) start keying off `req.user.id` for real (currently fall back to IP — see `throttler.config.ts` comment).

**Plan 10 (web /settings/security):**
- Consumes `GET /2fa/methods` and `DELETE /2fa/methods/:id`. Shape match enforced by `@simplevault/shared/zod`'s `TwoFaMethodSchema` + `TwoFaMethodsListSchema`. The 409 `AUTH_2FA_REMOVAL_BLOCKED` envelope (`data.requires:"shared_vault_2fa"`) is documented for the UI's clear-error surface.

**Phase 07 (vault.* + shared vaults):**
- Replace `userHasSharedVaultDependency` body with:
  ```ts
  const r = await this.db.db.execute<{ exists: boolean }>(sql`
    SELECT EXISTS(SELECT 1 FROM vault_members WHERE user_id = ${userId} LIMIT 1)
  `);
  return r.rows[0]?.exists ?? false;
  ```
- The integration test `2fa-removal.spec.ts` stays green because it injects its own stub via `MethodsService.sharedVaultDependencyCheck`.
- The first commit of Phase 07 should ALSO delete the probe route per Plan 07's hand-off rule (out of scope here).

**Plan 12 (E2E + runbook):**
- E2E spec (Cypress): enrol passkey + TOTP, list shows 2 → delete passkey → 204 + audit log row → list shows 1 → delete TOTP → 204 (count=0; deps stub returns false → ok). Cross-user delete attempt → 404 (NOT 403). Add a happy-path 409 test by directly poking the `vault_members` table once Phase 07 lands.

---

## Files

**Created:**
- `apps/api/src/twofa/methods/methods.controller.ts` (~95 lines)
- `apps/api/src/twofa/methods/methods.service.ts` (~210 lines including the dep stub + removeGuarded)
- `apps/api/test/2fa-removal.spec.ts` (~115 lines, 5 specs)

**Modified:**
- `apps/api/src/twofa/twofa.module.ts` (register MethodsController + MethodsService in the imports + providers + exports lists)
- `apps/api/src/common/throttler.config.ts` (twoFaMethodsListUser, twoFaMethodsDeleteUser ceilings + userKeyed expansion)
- `apps/api/src/common/audit-events.ts` (TwoFaMethodRemoved)
- `packages/shared/src/zod/index.ts` (TwoFaMethodSchema + TwoFaMethodsListSchema)
- `packages/shared/src/error-codes.ts` (AUTH_2FA_REMOVAL_BLOCKED = E1018)

---

## Next plans unblocked

- **Plan 07** (Require2FAGuard + probe) — consumes the same `countActive` semantics; circular-import-safe via the count-reader interface.
- **Plan 10** (web /settings/security) — needs the API endpoints; now available.
