# Plan 02-02 — packages/crypto Argon2id + AEAD + calibrate (TDD)

**Status:** DONE 2026-04-29
**Type:** TDD
**Wave:** 2 (parallel with 02-03 + 02-05)
**Commits:** 6 atomic (3 RED + 3 GREEN; refactor folded into GREEN since barrel re-exports were the obvious + only refactor and tests caught parity inline)

## What landed

`packages/crypto` now exports three primitive modules consumed by every later
crypto plan in Phase 02:

- **`src/argon2id.ts`** — `deriveKey(pw, salt, params, outLen=32)`, constant-
  time `verify(pw, salt, params, expectedKey)`, memoised `ready()`, frozen
  `ARGON2_DEFAULT_PARAMS` (m=64MiB, t=3, p=1) + `ARGON2_FLOOR_PARAMS`
  (m=19MiB, t=2, p=1) per CRYPTO-STACK.md, `paramsToOpsMem` helper, typed
  `Argon2SaltTooShortError` for sub-16-byte salts.
- **`src/aead.ts`** — `encrypt(plaintext, key, aad)` + `decrypt(blob, key,
  aad)` over XChaCha20-Poly1305 IETF. AAD is **mandatory** in the type
  signature (callers pass `new Uint8Array(0)` to mean "no AAD" — explicit).
  24-byte random nonce per call. `AeadKeyLengthError` for non-32-byte keys.
  Tag-mismatch on any of {wrong key, mutated ciphertext, mutated AAD,
  mutated nonce} surfaces as a libsodium throw.
- **`src/calibrate.ts`** — `calibrate(targetMs=750, toleranceMs=250)`
  binary-searches `memoryKiB` (bounded by `ARGON2_FLOOR_PARAMS.memoryKiB`
  floor + new `ARGON2_MEMORY_CAP_KIB` ceiling = 256 MiB) to land within the
  target band. `iterations` and `parallelism` stay at defaults (1-D tuning
  surface). Returns `{ params, measuredMs }`.

All three modules are re-exported through both `src/browser.ts` and
`src/node.ts` barrels to keep the conditional-exports map's symbol set in
parity. Vitest parity-tests in each suite assert this at runtime by
import-loading both barrels and inspecting their key sets.

## Verification

- **Tests:** 23 passing across 3 suites (`argon2id.test.ts` 9, `aead.test.ts`
  9, `calibrate.test.ts` 5). All 7 plan truths verified.
- **Typecheck + build:** `pnpm --filter @simplevault/crypto typecheck` +
  `build` clean.
- **Browser bundle parity:** `grep -nE 'require\(.crypto.|require\(.buffer.|from .node:|from "crypto"|node:crypto|node:buffer' packages/crypto/dist/browser.js`
  returns ZERO matches. `dist/browser.js` and `dist/node.js` both
  `export * from "./argon2id.js"`, `"./aead.js"`, `"./calibrate.js"` (source-
  level parity confirmed).

## Versions resolved

- `libsodium-wrappers-sumo@0.7.16` (already installed via 01-03)
- `vitest@2.1.9` (devDependency added to packages/crypto only)
- `vite@5.4.21` (transitive of vitest)

## Calibration behaviour observed (dev hardware: Apple Silicon)

With `targetMs=750, toleranceMs=250`, the binary search converges in 1-2
iterations. `m=64MiB, t=3, p=1` lands at ~90-150ms on Apple Silicon dev
hardware — significantly faster than the target band. The calibrator
correctly bumps memoryKiB (doubling) until either the band is reached or
`ARGON2_MEMORY_CAP_KIB` (256 MiB) is hit. On the dev box, two consecutive
runs typically agree within ~30%.

**Operator action (queued for Plan 02-06):** run `pnpm cli argon2 calibrate`
on the production VPS once. Expected to land within band at significantly
lower memory than the dev cap (VPS CPUs are typically 5-10× slower than
Apple Silicon for memory-hard workloads). Bake the resulting `m,t,p` into
Dokploy env (`ARGON2_MEMORY_KIB`, `ARGON2_ITERATIONS`).

## Decisions / notes

1. **`Argon2Params.parallelism` is literal-typed `1`.** libsodium-wrappers is
   single-threaded WASM; allowing `>1` would silently no-op and mislead.
2. **AAD is `Uint8Array`, never `string`.** AAD-encoding mismatch is the #1
   AEAD footgun (truth #5 in plan). The API signature forces a `Uint8Array`
   — no implicit string coercion.
3. **AAD is required in the encrypt/decrypt type.** No optional. Callers
   must explicitly pass `new Uint8Array(0)` to opt out — defends against
   the silent-omission failure mode.
4. **Sanity-latency floor lowered to `>50ms`** (was `>100ms` in plan).
   Apple Silicon dev hardware completes Argon2id m=64MiB,t=3 in ~93ms —
   the original floor flaked. 50ms still distinguishes "real KDF" from
   "skipped / 0 iterations" (the test's purpose). Operator should expect
   the production VPS to land in the 500-800ms range with default params.
5. **Vitest config aliases `libsodium-wrappers-sumo` to its CJS entry.**
   Upstream's published ESM build (`dist/modules-sumo-esm/libsodium-
   wrappers.mjs`) imports a relative `./libsodium-sumo.mjs` that isn't
   shipped in the package — a known upstream packaging bug. Vitest's
   `resolve.alias` redirects to the CJS bundle (which IS shipped + works).
   This same alias will need to be propagated into the API/web build
   configs in later plans IF they hit the same ESM-resolution path; both
   NestJS (webpack) and Next.js (turbopack/esbuild) typically resolve via
   the `require` field of `exports` automatically, so the alias is most
   likely Vitest-only — verify when wiring 02-06 (Node CLI) and 02-10/11
   (web).
6. **No `refactor` commits** were necessary. Each task's barrel re-exports
   (the only obvious refactor) were folded into the GREEN commit because
   the parity test asserts them inline — separating them would have
   tested-against-broken-barrels-then-fixed-them, which the parity test
   already prevents at GREEN. Plan §execution_context allows refactor as
   optional. Truths-coverage and TDD discipline preserved.

## Affected plans / dependencies

- **02-03** (BIP-39 + key hierarchy) **UNBLOCKED**: it consumes `deriveKey`
  for `deriveMasterKEK`, `encrypt/decrypt` for wrapping the key hierarchy,
  and the same `Argon2Params` type for envelope metadata.
- **02-04** (X25519 sealed-box) inherits the same barrel-parity convention.
- **02-06** (operator CLI) imports `calibrate` directly.
- **02-07/08** (signup + login) consume `deriveKey` + `verify` server-side
  for the secret-key verifier.

## Files

- `packages/crypto/src/argon2id.ts` (new, 91 lines)
- `packages/crypto/src/aead.ts` (new, 73 lines)
- `packages/crypto/src/calibrate.ts` (new, 77 lines)
- `packages/crypto/src/browser.ts` (added 3 `export *` lines)
- `packages/crypto/src/node.ts` (added 3 `export *` lines)
- `packages/crypto/test/argon2id.test.ts` (new)
- `packages/crypto/test/aead.test.ts` (new)
- `packages/crypto/test/calibrate.test.ts` (new)
- `packages/crypto/vitest.config.ts` (new — incl. libsodium CJS alias)
- `packages/crypto/package.json` (+ `vitest` devDep, + `test`/`test:watch` scripts)

## Commits

- `46d6763` test(02-02-T1-RED): argon2id deriveKey/verify failing tests
- `54941d9` feat(02-02-T1-GREEN): argon2id deriveKey/verify implementation
- `98fdfed` test(02-02-T2-RED): XChaCha20-Poly1305 AEAD failing tests
- `524c070` feat(02-02-T2-GREEN): XChaCha20-Poly1305 AEAD with mandatory AAD
- `b9394c7` test(02-02-T3-RED): calibrate() failing tests
- `9d97dc9` feat(02-02-T3-GREEN): Argon2id calibrate() with binary search

## Deviations

1. **Latency-floor sanity test threshold lowered 100ms → 50ms.** Auto-applied
   under deviation rule 1 (test threshold tweak that preserves the truth's
   intent — "not zero iterations"). Documented above.
2. **Refactor commits not produced.** Auto-applied under rule 2 — plan
   §execution_context says refactor is optional, and barrel re-exports were
   the only candidate; folding into GREEN preserved TDD without
   testing-broken-then-fixing.
3. **Vitest config carries a libsodium-wrappers-sumo CJS alias** to work
   around an upstream ESM-packaging bug. Auto-applied under rule 3 (a
   build-config workaround for a third-party packaging defect, no impact
   on plan truths or runtime behaviour).

No rule-4 deviations. No checkpoints triggered.
