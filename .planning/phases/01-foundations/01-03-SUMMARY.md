# Plan 01-03 Summary — Shared / Crypto / DB skeletons

**Phase:** 01-foundations
**Plan:** 03
**Wave:** 3
**Status:** COMPLETE
**Date:** 2026-04-28

## What was delivered

Three workspace packages registered, all building / typechecking / linting clean:

1. **`@simplevault/shared`** — error code map (E1xxx auth / E2xxx vault / E3xxx crypto / E4xxx validation / E5xxx server) as `as const` map (no enum per lint rule), `HealthResponseSchema` Zod placeholder, barrel index. Subpath exports `./errors` and `./zod`.
2. **`@simplevault/crypto`** — branded crypto types (Plaintext / Ciphertext / Nonce / Salt / SymmetricKey / WrappedKey / RecoveryPhrase), `CryptoApi` interface (`randomBytes`, `deriveMasterKEK`, `wrapKey`, `unwrapKey`, `encrypt`, `decrypt`, `bip39Generate`, `bip39ToSeed`, `chainHashCompute`, `chainHashVerify`), and stub implementations in `browser.ts` + `node.ts` that throw "not yet implemented (Phase 02)". Phase 02 fills these in under the `crypto-auditor` gate.
3. **`@simplevault/db`** — Drizzle ORM `createDbClient(options)` factory returning `{ db, pool }` with sensible pool defaults (max 10, 30s idle, 5s connection timeout), `users` schema stub (`id` uuid pk default random, `email` text unique not null, `created_at` timestamptz not null default now), schema barrel, and `drizzle.config.ts` (`postgresql` dialect, schema path, `./drizzle` migrations out, strict + verbose). Server-only — no `browser` condition in exports map.

## Resolved dependency versions (from pnpm-lock.yaml)

| Spec | Resolved |
|---|---|
| `zod ^3.24.0` | `3.25.76` |
| `libsodium-wrappers-sumo ^0.7.15` | `0.7.16` |
| `@noble/hashes ^1.6.0` | `1.8.0` |
| `bip39 ^3.1.0` | `3.1.0` |
| `drizzle-orm ^0.38.0` | `0.38.4` |
| `drizzle-kit ^0.30.0` | `0.30.6` |
| `pg ^8.13.0` | `8.20.0` |
| `@types/pg ^8.11.0` | `8.20.0` |
| `@types/libsodium-wrappers-sumo ^0.7.0` | (latest 0.7.x; pulls in deprecated `@types/libsodium-wrappers@0.8.2` as a subdep — benign) |

## Load-bearing artifact: `@simplevault/crypto` exports map

Order verified in `packages/crypto/package.json`:

```json
"exports": {
  ".": {
    "types": "./dist/index.d.ts",
    "browser": "./dist/browser.js",
    "node": "./dist/node.js",
    "default": "./dist/node.js"
  },
  "./types": { "types": "./dist/types.d.ts", "import": "./dist/types.js" }
}
```

`browser` precedes `node` precedes `default` — so Webpack 5 / Turbopack / Next.js bundlers resolving `target: web` pick `dist/browser.js`, while NestJS / direct Node imports get `dist/node.js`. Both files exist post-build (verified by `ls packages/crypto/dist/`).

The package also has top-level `"main": "./dist/node.js"` and `"browser": "./dist/browser.js"` for tools that don't honor `exports`.

## Deviations from plan

- **`browser.ts` / `node.ts` stub typing**: plan template used `notImplemented(...) as never` cast inside async arrow bodies. With ESLint strict-type-checked `@typescript-eslint/require-await` and `@typescript-eslint/no-confusing-void-expression`-adjacent rules, that pattern flagged unnecessary-cast and async-without-await issues. Adjusted: `notImplemented` returns `never`, async signatures are wrapped as `() => Promise.resolve(notImplemented(...))` (Promise.resolve of a `never`-typed throw is fine and avoids the unused-async warning). Same `CryptoApi` shape and behavior.
- **`packages/crypto/src/index.ts`**: removed the `Nonce` named import from the types barrel (it was unused after the interface definitions; would trigger `noUnusedLocals`). All branded types are still re-exported via `export type *`.
- **`packages/db/src/client.ts`**: split the imports into two groups (external first, then internal `./schema/...`) per `import/order` lint rule with `newlines-between: always`.
- `packages/tsconfig/library.json` still has `composite: true`. None of the three new packages declare project references, but each builds standalone via `tsc -p tsconfig.json`. Root `pnpm build` (turbo) builds all three in topological order without issue. No deviation needed.

## Verifies (all passed)

- `pnpm --filter @simplevault/{shared,crypto,db} build` — exit 0
- `pnpm --filter @simplevault/{shared,crypto,db} typecheck` — exit 0
- `pnpm --filter @simplevault/{shared,crypto,db} lint` — exit 0
- `dist/` artifacts present for all three packages, including `packages/crypto/dist/{browser,node,index}.js`
- `pnpm build`, `pnpm typecheck`, `pnpm lint` from root — all 3/3 successful
- `drizzle.config.ts` `dialect: "postgresql"` confirmed by grep

## Commits

- `feat(01-03-T1): @simplevault/shared (error codes + Zod placeholder)` — `13811be`
- `feat(01-03-T2): @simplevault/crypto skeleton with browser/node exports` — `e4ba914`
- `feat(01-03-T3): @simplevault/db skeleton + users schema` — `736148a`

## Wave 4 hand-off notes

- `apps/api` will import `@simplevault/db` (`createDbClient`, `schema`) + `@simplevault/shared/errors` + `@simplevault/crypto` (gets `dist/node.js`).
- `apps/web` will import `@simplevault/shared` + `@simplevault/crypto` (Next.js bundler picks `dist/browser.js`). Must NOT import `@simplevault/db` — plan to add this restriction in `packages/eslint-config/next.js` if not already there.
- `pg-Pool` is configured server-side only; `apps/web` should never reach it.
- Drizzle 0.38.x + drizzle-kit 0.30.x + pg 8.20 are wire-protocol-compatible with PostgreSQL 18.3 (no PG-15-specific features used).
- Stub crypto throws are intentional. Wave 4 should NOT be implementing crypto operations — only wiring the import shape. Real crypto lands in Phase 02 under the `crypto-auditor` gate.
