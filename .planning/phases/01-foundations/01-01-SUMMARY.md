# Plan 01-01 — Root Scaffold (SUMMARY)

**Status:** COMPLETE
**Date:** 2026-04-28
**Wave:** 1
**Tasks:** 2/2

## Files created

### Task 1 — Turborepo + pnpm workspace
- `package.json` — root, private, `packageManager: pnpm@9.15.0`, engines `node>=22 / pnpm>=9`, workspace scripts (`dev`, `build`, `lint`, `typecheck`, `test`, `clean`).
- `pnpm-workspace.yaml` — globs `apps/*`, `packages/*`.
- `turbo.json` — tasks `build / lint / typecheck / dev / test / clean` with `^build` chains; `globalPassThroughEnv` for `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `SERVER_CHAIN_SECRET`, `NODE_ENV`.
- `.npmrc` — `strict-peer-dependencies=true`, `auto-install-peers=false`, `shared-workspace-lockfile=true`, `shamefully-hoist=false`, `node-linker=isolated`.
- `.nvmrc` — `22`.
- `.gitignore` — Node + Turborepo standard (node_modules, .next, dist, .turbo, coverage, .env / .env.local / .env.*.local, *.log, .DS_Store, tmp/, out/, *.tsbuildinfo). `.env.example` NOT ignored.
- `.editorconfig` — LF, utf-8, 2-space indent, final newline; Markdown overrides `trim_trailing_whitespace=false`.
- `pnpm-lock.yaml` — generated from clean install.

### Task 2 — Workspace structure + base TS config
- `tsconfig.base.json` — strict, `target: ES2023`, `moduleResolution: bundler`, plus `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`, `verbatimModuleSyntax`, `isolatedModules`, incremental builds.
- `apps/.gitkeep`
- `packages/.gitkeep`

## Lockfile sanity check

- `pnpm-lock.yaml` — 113 lines / 3,078 bytes.
- 6 packages resolved (turbo, typescript, prettier, @types/node + 2 transitive).
- `pnpm install` from clean state: ~2.1s.

## Verification

- `pnpm install` → exit 0, no peer-dep errors.
- `pnpm exec turbo run build` → exit 0, "No tasks were executed as part of this run." (expected: zero apps/packages yet).
- `cat package.json | jq .name` → `"simplevault"`.
- `find apps packages -maxdepth 1 -type d` → both directories present.
- `git ls-files` shows all five tracked dotfiles + tsconfig.base.json + .gitkeep stubs.

## Deviations

None. Plan followed verbatim.

Minor environment note (not a deviation): the host has pnpm 10.33.2 / Node 25 installed locally, both well above the `>=9` / `>=22` engine floors. The `packageManager` field still pins `pnpm@9.15.0` per spec, so corepack-aware setups will use 9.15.0 deterministically.

## Decisions made

- Adopted `node-linker=isolated` in `.npmrc` (per spec) — strictest pnpm linking, surfaces undeclared-dep imports immediately.
- `globalPassThroughEnv` (not per-task) chosen for the runtime secrets so each task inherits identically; runtime tasks (dev / test) need them for integration tests downstream.
- No `Co-Authored-By` trailer added — the existing repo history (5 commits) does not use it.

## Commits

- `e8eaa04` — `feat(01-01-T1): initialize turborepo + pnpm workspace`
- `01d7466` — `feat(01-01-T2): add base tsconfig + workspace dirs`
- (final) — `docs(01-01): complete root scaffold plan`

## Downstream unblocks

- Wave 2 / Plan 02 (`tsconfig + eslint packages`) can now extend `tsconfig.base.json` and consume the workspace.
- Every subsequent plan can register itself as an `apps/<name>` or `packages/<name>` workspace.
