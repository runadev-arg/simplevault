# Plan 04-06 Summary — Web typed credentials API client

**Status:** CLOSED — 2 atomic commits, web build + 46/46 tests green.

## Commits

- `feat(04-06-T1): credentials-client typed wrappers + base64url encoding`
- `feat(04-06-T2): VersionConflictError + 409/404/413 error mapping + spec`

## Artifacts

| Path                                                          | Role                                                         |
| ------------------------------------------------------------- | ------------------------------------------------------------ |
| `apps/web/src/lib/api/credentials-client.ts`                  | Typed wrappers `createCredential` / `getCredential` / `updateCredential` / `deleteCredential` / `listVaultPersonal` |
| `apps/web/src/lib/api/base64url.ts`                           | `bytesToB64Url` / `b64UrlToBytes` (libsodium URLSAFE_NO_PADDING) |
| `apps/web/src/lib/api/errors.ts`                              | `VersionConflictError`, `CredentialNotFoundError`, `CredentialBodyTooLargeError`, `mapCredentialError`, `ApiError` alias |
| `apps/web/src/lib/api/credentials-client.test.ts`             | 9 tests — happy paths + base64url boundary + 404/409/413 mapping |

## Truths landed

1. ✅ All five wrappers exported with typed responses; per-credential
   wrappers map known error codes to typed `AuthClientError` subclasses.
2. ✅ `updateCredential` 409 → `VersionConflictError` carrying
   `{credentialId}`. Caller pattern: `try { ... } catch (e) { if (e instanceof VersionConflictError) ... }` — verified in spec.
3. ✅ All wrappers go through the existing Phase-02 `request` helper
   (auth-client.ts) — no duplicate fetch logic. `grep "fetch(" credentials-client.ts` returns zero matches.
4. ✅ Wire shape: ciphertext / nonce sent as base64url strings; response
   decode reverses to `Uint8Array`. Spec asserts both directions byte-for-byte.
5. ✅ `pnpm --filter @simplevault/web build && test` green (46 tests, 7 files).

## Design notes

### apiFetch error-mapping — wrap-and-rethrow at the per-wrapper site

The plan suggested either (a) extend the central `request`/`apiFetch`
switch or (b) wrap-and-rethrow at the per-credential wrapper. We chose
**(b)** — `mapCredentialError(e, {credentialId})` runs inside the
`try/catch` of each wrapper that touches `:id`. Rationale:

- Phase-02 / Phase-03 callers (auth-client, sessions-client, twofa-client)
  stay byte-equal — no risk of accidentally retyping their errors.
- The wrap site is the only place that knows the URL-bound `credentialId`
  needed by `VersionConflictError`. Pulling that out of the URL inside
  `request` would require parsing the path string, which is fragile.
- Single-purpose: `errors.ts` owns the code → subclass map; the wrappers
  own the id → context map.

### `VersionConflictError.credentialId` source-of-truth

The id comes from the wrapper's `id: string` parameter, NOT from the
server's 409 body (which only carries `{error: {code, message}}` per the
project's uniform envelope). The wrapper passes `{credentialId: id}` to
`mapCredentialError`; `listVaultPersonal` and `createCredential` (no `:id`
in the URL) pass no context — `VersionConflictError` is unreachable from
those paths anyway since the server only emits 409 on `PATCH`.

### `ApiError` alias instead of a fresh base class

`AuthClientError` is the project's existing base for `{error.code, status, message}` — Plans 02-11 / 03-08 / 03-10 / 03-11 already throw and catch it. Rather than introduce a parallel `ApiError` hierarchy and migrate every existing catcher, `errors.ts` re-exports `AuthClientError as ApiError`. The plan's `class VersionConflictError extends ApiError` contract holds; existing `instanceof AuthClientError` catchers continue to match (verified in the spec — `caught` is simultaneously `instanceof VersionConflictError`, `ApiError`, and `AuthClientError`).

### Base64url boundary

The wire contract is **base64url, no padding** (per Plan 04-02 DTO comments and Truth 7's parity with libsodium). The helper defers to libsodium-wrappers-sumo's `to_base64` / `from_base64` with `URLSAFE_NO_PADDING` — no DIY base64 implementation. `sodium.ready` is awaited by every credentials caller in the surrounding crypto pipeline, so the helper is safe to call synchronously by then.

## Deviations from the plan

1. **Plan named the helper `apiFetch`; the project's helper is `request`.** The plan's `@apps/web/src/lib/api/api-fetch.ts` reference does not exist — Phase-02 (Plan 02-08) shipped the canonical helper as `request` exported from `auth-client.ts`. We use `request` and document this here. Functional equivalence: same error-envelope handling, same `AuthClientError` throwing, same `accessToken: Bearer` header injection, same Zod-validation on success, same 204 short-circuit.
2. **Extended `request`'s method union to include `"PATCH"`.** Phase-02/03 only used GET/POST/DELETE. One-line change in `auth-client.ts` so `updateCredential` can route through the same plumbing.
3. **No MSW dependency.** Plan suggested MSW; the project's vitest config is intentionally minimal. We mock `globalThis.fetch` directly — same coverage (URL / method / headers / body assertions), zero new deps.
4. **Wrappers take `accessToken: string` as first arg** (matches `sessions-client.ts` / `twofa-client.ts` convention) rather than reading it from a hidden module-scope token store. The Plan 04-09 / 04-10 UI will pass `useAuth().accessToken` through.

## Cross-plan handoffs

- **Plan 04-09** imports `listVaultPersonal` + `getCredential` for the vault list + lazy detail load.
- **Plan 04-10** imports `createCredential` + `updateCredential` + `deleteCredential` and catches `VersionConflictError` to drive the edit-form retry UX (re-fetch via `getCredential`, re-apply local edits, retry PATCH).
- **Plan 04-12** Cypress `credentials-crud.cy.ts` asserts the 409 + 404 mapping end-to-end against the real API.
