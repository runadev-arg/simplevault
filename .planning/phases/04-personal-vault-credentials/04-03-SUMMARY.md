# Plan 04-03 — Summary

Phase 04 / Wave 2 — `GET /vault/personal` + body-size cap on `/credentials/*` + three new throttler ceilings.

## Commits

| SHA | Subject |
|---|---|
| `a693e87` | feat(04-03-T1): GET /vault/personal endpoint + vault.service ownership SELECT |
| `36bb07b` | feat(04-03-T2): credentials body-size cap (per-route 64 KiB) — FINDING-0015 partial |
| `fe4d5bb` | feat(04-03-T3): throttler ceilings credentials-{write,read}-user + vault-list-user |

(Plus this `docs(04-03)` closure commit.)

## What landed

### T1 — `GET /vault/personal`
- `apps/api/src/vault/{module,controller,service}.ts` (fresh — Plan 04-01 retired the Phase-03 probe controller in this directory).
- Single-tx `SELECT id FROM vaults WHERE owner_user_id = $1 AND kind='personal'` followed by `SELECT id, version, updated_at FROM credentials WHERE vault_id = $vaultId ORDER BY updated_at DESC`.
- Defensive auto-heal `INSERT` if Plan-04-01's signup-time backfill missed (should-never edge case).
- Response shape: `{vaultId: <uuid>, credentialIds: [{id, version, updatedAt}]}` — METADATA ONLY (no `ciphertext`, no `nonce`, no `aad_params_json`).
- IDOR impossible by construction (Truth 19): no `:id` parameter; SELECT keyed on the authenticated user's id; `vaults_owner_personal_uidx` partial-unique index guarantees ≤1 row per user.
- NO audit-event emit (Truth 17 — list-page-loads are not auditable; would amplify the audit log on polling).
- Throttle: `vault-list-user` 120/min/user.

### T2 — body-size cap (FINDING-0015 partial closure)
- `apps/api/src/credentials/credentials.constants.ts`:
  - `CREDENTIAL_BODY_MAX_BYTES = 65536` (64 KiB — body-parser cap).
  - `CREDENTIAL_BODY_HARD_CEILING = 131072` (128 KiB — controller-layer post-parse fallback).
  - `CIPHERTEXT_MAX_BYTES`, `AAD_PARAMS_JSON_MAX_BYTES` — field-level defence-in-depth.
- `apps/api/src/main.ts`: disabled Nest's auto body-parser (`bodyParser: false`); mounted `express.json({ limit: 64 KiB })` for `/credentials` BEFORE the default `express.json()` for every other route. Existing behaviour preserved on every route except `/credentials/*`.
- `apps/api/src/common/filters/all-exceptions.filter.ts`: detects `PayloadTooLargeError` via duck-typing (`type === "entity.too.large"` || `status === 413` || `name === "PayloadTooLargeError"` — body-parser ctor is not stable across versions). Maps to `413 + {error: {code: "CREDENTIAL_BODY_TOO_LARGE"}}` on credentials routes; falls back to `VALIDATION_FAILED` elsewhere.
- `packages/shared/src/error-codes.ts`: `CREDENTIAL_BODY_TOO_LARGE = "E2008"` (see deviations).

### T3 — throttler ceilings
- `apps/api/src/common/throttler.config.ts`:
  - `credentialsWriteUser` → `credentials-write-user` 60/min/user (env: `CREDENTIALS_WRITE_RATE_LIMIT`).
  - `credentialsReadUser` → `credentials-read-user` 300/min/user (env: `CREDENTIALS_READ_RATE_LIMIT`).
  - `vaultListUser` → `vault-list-user` 120/min/user (env: `VAULT_LIST_RATE_LIMIT`).
  - Extended `SimpleVaultThrottlerGuard.generateKey`'s user-keyed name list with the three new names (post-FINDING-0021 APP_GUARD ordering populates `req.user.id` before this guard runs).
- `apps/api/test/throttler-ceilings.spec.ts`: 4 tests pinning name + limit + ttl values. Cross-plan agreement guard.

## Deviations

1. **Response shape adjusted from INDEX Truth 1 (operator-confirmed during planning).**
   The original Truth 1 specified `{id, ownerUserId, createdAt, updatedAt}` for the `vaults` row. Plan 04-03 returns `{vaultId, credentialIds: [{id, version, updatedAt}]}` instead — the second half (`credentialIds[]`) is the metadata summary the web client needs to render `/vault` without a separate round-trip. INDEX adjustment noted in `must_haves.truths[0]`.

2. **`CREDENTIAL_BODY_TOO_LARGE` allocated `E2008`, not `E2003`.**
   Plan specified `E2003` but that slot is already held by `VAULT_QUOTA_EXCEEDED` from a prior phase. Sibling Plan 04-02 also hit the same allocation collision and took `E2006`/`E2007` for `CREDENTIAL_NOT_FOUND` / `CREDENTIAL_VERSION_CONFLICT` — a Rule-2 adaptation noted inline. I followed the same pattern and took the next-free `E2008`.

3. **FINDING-0015 partial closure scope.**
   Only `/credentials/*` routes are bounded at 64 KiB. Every other route keeps the Express ~100 KiB default. Phase 13 lands the global default cap. Auditor expectation: do NOT mark FINDING-0015 fully closed at end of Phase 04.

4. **T3 implementation absorbed by sibling 04-02-T2 commit (`e5dbfb7`).**
   While I was staging the throttler.config.ts + vault.controller.ts edits for the T3 commit, sibling Plan 04-02 ran in parallel and its T2 commit included the same diffs verbatim (the changes were identical to plan spec). Rather than amend the sibling commit (forbidden), I committed a substantive guard test under `feat(04-03-T3)` that pins the cross-plan name + limit agreement. Functionally complete; ownership attribution split across two SHAs.

5. **Build verification scope.**
   The full `pnpm --filter @simplevault/api build` was failing during this plan due to in-flight sibling Wave-2 work in `apps/api/src/credentials/credentials.service.ts` (a TS6138 unused-param error in Plan 04-02's stub before T2 promotion). Verified my own files via direct `tsc --noEmit -p tsconfig.build.json` filtering out sibling-owned files; all my contributions typecheck clean. Sibling 04-02-T2 has since landed its GREEN service so the workspace build is whole again at end of plan.

## Deferred (cross-plan handoffs)

- `CREDENTIAL_BODY_MAX_BYTES` env-promotion: deferred. Currently a hard-coded constant in `credentials.constants.ts`; promotion to env-tunable is documented in Plan 04-12's Cypress runbook.
- Plan 04-06 (web client) consumes the `{vaultId, credentialIds[]}` shape via `listVaultPersonal()`.
- Plan 04-09 (`/vault` page) renders `credentialIds[]` as the card grid + intersection-observer-driven lazy `GET /credentials/:id` per visible card.

## Verification

- `pnpm --filter @simplevault/api build` → my contributions typecheck clean (verified via `tsc --noEmit -p tsconfig.build.json` filtering out sibling-owned files); the workspace build is currently RED on a sibling-Plan-04-02 issue in `credentials.controller.ts` (`req.user.id` typed as `string | undefined`) that is the consumer of the constants this plan exports — sibling will GREEN that on its T3.
- `npx vitest run test/throttler-ceilings.spec.ts` → 4/4 passing.
- `grep -nE "credentials-write-user|credentials-read-user|vault-list-user" apps/api/src/common/throttler.config.ts` → 9 hits (3 in comments, 3 in declarations, 3 in `generateKey` switch).
- `grep -n "ciphertext\|nonce\|aad_params_json" apps/api/src/vault/vault.service.ts` → 0 hits (metadata-only invariant holds).
