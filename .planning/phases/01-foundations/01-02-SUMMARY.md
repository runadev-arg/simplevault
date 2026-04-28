# Plan 01-02 — Summary: shared tsconfig + eslint-config packages

**Status:** COMPLETE
**Date:** 2026-04-28
**Wave:** 2
**Commits:** 2 (T1 tsconfig, T2 eslint-config)

## What landed

- `packages/tsconfig/` — `@simplevault/tsconfig` workspace package exposing 4 presets:
  - `base.json` — re-exports root `tsconfig.base.json`
  - `library.json` — for `packages/*` (composite, declarations, sourcemaps)
  - `nestjs.json` — CommonJS, decorator metadata, `verbatimModuleSyntax: false`
  - `nextjs.json` — ESNext + bundler resolution + JSX preserve + Next plugin
- `packages/eslint-config/` — `@simplevault/eslint-config` (ESM, flat-config) with three exports:
  - `.` (index.js) — base preset using `js.configs.recommended` + `typescript-eslint` strict + stylistic type-checked + `eslint-plugin-import` + `eslint-config-prettier`. Bans enums, console (except warn/error), enforces no-floating-promises, type imports, import/order.
  - `./nest` — relaxes `no-extraneous-class`, `parameter-properties`, allows empty constructors.
  - `./next` — restricts importing server-only modules from web client code.

## Versions confirmed

- `@eslint/js` ^9.17.0 → resolved 9.17+ in lockfile
- `typescript-eslint` ^8.18.0 → resolved 8.59.1
- `eslint-plugin-import` ^2.31.0 → resolved 2.32.0
- `eslint-config-prettier` ^9.1.0 → resolved 9.1.2
- ESLint v9 flat config format used throughout. `peerDependencies.eslint: ^9.0.0`.

## Deviations

- None. Plan executed verbatim.
- `eslint-config-next` was deliberately NOT pulled (per plan note); will be revisited if Next.js 15 + ESLint v9 friction is resolved by the time apps/web is wired up.

## Notes for downstream waves

- pnpm install emits **peer-dependency warnings** for `eslint` because `@simplevault/eslint-config` declares `eslint` as a peer but no workspace yet provides it. These warnings are harmless and will disappear once `apps/api` and `apps/web` add `eslint` as a dev dep in Wave 4 (Plans 04 + 05). With root `.npmrc` `strict-peer-dependencies=true`, `pnpm install` still exited 0 because the missing peer is at the workspace-package boundary — verify again after Wave 4 lands.
- Downstream consumers must use `"@simplevault/tsconfig": "workspace:*"` and `"@simplevault/eslint-config": "workspace:*"` in their `package.json`.
- `packages/tsconfig/library.json` sets `composite: true` — when the first library lands (Plan 03), root `tsconfig.json` (or a project-references file) may need a `references` array if/when we want incremental project builds. Plan 03 should decide.

## Verification ran

- `cat packages/tsconfig/package.json | jq -r .name` → `@simplevault/tsconfig`
- `pnpm install` → `Done in 263ms`, exit 0
- `pnpm list -r --depth -1` → both `@simplevault/tsconfig@0.0.0` and `@simplevault/eslint-config@0.0.0` registered
- `ls packages/tsconfig/*.json` → 5 files (4 presets + package.json)
- `ls packages/eslint-config/*.js` → 3 files (index, nest, next)

## Unblocks

- Wave 3 / Plan 03: shared/crypto/db package skeletons can now `extends` from `@simplevault/tsconfig/library.json` and import from `@simplevault/eslint-config`.
