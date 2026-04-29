---
Date: 2026-04-28
Auditor: dependency-supply-chain-auditor
Scope: Phase 01 — package.json (root + apps/* + packages/*), pnpm-lock.yaml,
       postinstall hooks, .npmrc, .nvmrc, .github/dependabot.yml,
       pnpm audit (prod), workspace protocol consistency, version pinning posture
Method: Read-only inspection of repo + `pnpm install --frozen-lockfile`
        + `pnpm audit --audit-level={high,moderate} --prod`
        + grep over node_modules/.pnpm for postinstall/preinstall/install scripts
        + `pnpm list --depth 0 -r` and node_modules/.pnpm enumeration
Verdict: FAIL (blocking) — 2 Critical + 7 High CVEs in production deps
---

# Dependency Supply-Chain Audit — Phase 01

## Summary

Phase 01 establishes the workspace skeleton (NestJS API, Next.js web,
crypto/db/shared packages, tooling). The repository hygiene around the
supply chain is **strong** (lockfile committed and clean, workspace
protocol used consistently, `auto-install-peers=false`,
`strict-peer-dependencies=true`, packageManager pinned, .nvmrc set,
dependabot configured). However, **9 high-or-critical CVEs are present
in production-affecting deps right now**, all of which are fixed by
upstream releases. The fixes are simple version bumps; this is a
**FAIL** until they are applied.

The most serious concerns are two critical CVEs in `next@15.1.0`
(RCE in React-flight protocol, authorization-bypass in middleware)
and a SQL-injection CVE in `drizzle-orm@0.38.4`. Both have patches.

`pnpm install --frozen-lockfile` exits 0 — no lockfile drift.

---

## Findings by Severity

### Critical

#### C-1. Next.js — RCE in React flight protocol (GHSA-9qr9-h5gf-34mp)
- Package: `next@15.1.0` (apps/web)
- Vulnerable: `>=15.1.0-canary.0 <15.1.9`
- Patched: `>=15.1.9`
- Path: `apps/web > next@15.1.0`
- Impact: Remote code execution surface in the public web app.
  This is the single most exposed component in the SimpleVault threat
  model (internet-facing, behind Dokploy at pass.runadev.com).
- Mitigation: Bump `next` to `>=15.5.15` (also fixes C-2, H-1, H-7
  and one moderate). Re-pin `eslint-config-next` to a matching version.

#### C-2. Next.js — Authorization Bypass in middleware (GHSA-f82v-jwr5-mffw)
- Package: `next@15.1.0` (apps/web)
- Vulnerable: `>=15.0.0 <15.2.3`
- Patched: `>=15.2.3`
- Path: `apps/web > next@15.1.0`
- Impact: Middleware-based auth checks can be bypassed by crafted
  requests. SimpleVault depends on Next middleware for any future
  session-gating logic; even though Phase 01 has no real auth wired
  yet, shipping this version is a hard no.
- Mitigation: same bump as C-1.

### High

#### H-1. Next.js DoS via cache poisoning (GHSA-67rr-84xm-4c7r)
- `next@15.1.0`, vulnerable `<15.1.8`, fixed in `>=15.1.8`. Same path
  as C-1/C-2; resolved by the same bump.

#### H-2..H-4. Multer — three DoS CVEs (incomplete cleanup, resource exhaustion, uncontrolled recursion)
- Package: `multer@2.0.2`, transitive of
  `@nestjs/platform-express@10.4.22`.
- Patched: `>=2.1.1`.
- Impact: Multer is the default body parser inside NestJS for
  multipart uploads. Phase 01 does not yet expose upload endpoints,
  but the dep is loaded. A trio of DoS vulnerabilities in a transitive
  Express upload module on an internet-facing API is unacceptable.
- Mitigation: bump `@nestjs/platform-express` (and ideally the rest of
  `@nestjs/*`) to `^11.x`, where multer is at >=2.1.1. If staying on
  Nest 10, add a `pnpm.overrides` entry forcing `multer: ">=2.1.1"`
  in root package.json and re-run install (still recommend going to
  Nest 11 in Phase 02).

#### H-5. lodash — code injection via `_.template` (GHSA-r5fr-rjxr-66jc)
- Package: `lodash@4.17.21`, transitive of `@nestjs/config@3.3.0`.
- Vulnerable: `>=4.0.0 <=4.17.23`. Patched: `>=4.18.0`.
- Mitigation: lodash@4.18.0 is not yet released as of audit date — no
  upstream patched version exists in the npm registry. **The advisory
  is currently unfixable by version bump**; this is an inherited
  CVE awaiting upstream release. Risk is bounded because
  `_.template` is not invoked by `@nestjs/config` against
  attacker-controlled input (config is loaded from local env / files
  at boot). Document and accept; revisit when lodash@4.18.x ships.
  Add a SECURITY note in the operator runbook.

#### H-6. drizzle-orm — SQL injection via improperly escaped identifiers (GHSA-gpj5-g38j-94v9)
- Package: `drizzle-orm@0.38.4` (packages/db, apps/api)
- Vulnerable: `<0.45.2`. Patched: `>=0.45.2`.
- Impact: Direct hit on the data-access layer of the entire vault.
  Even with parameterised queries, identifier-escaping issues become
  injection vectors when any code path takes a column/table name
  from a non-static source. This is the highest-risk finding in the
  data tier.
- Mitigation: bump `drizzle-orm` (and `drizzle-kit` for compatibility)
  to `^0.45.2` or newer. Re-run `pnpm db:generate` and verify schema.

#### H-7. Next.js DoS with Server Components (GHSA-q4gf-8mx6-v5v3)
- `next@15.1.0`, vulnerable `<15.5.15`, fixed `>=15.5.15`. Resolved
  by the same Next bump as C-1/C-2/H-1.

### Medium

#### M-1. pnpm audit — 13 moderate vulnerabilities
- `@nestjs/core` injection issue (fixed in Nest 11.1.18) — included
  in the H-2..H-4 fix path (upgrade to Nest 11).
- `postcss <8.5.10` XSS via unescaped `</style>` — transitive via
  `next@15.1.0`; bumping Next clears it.
- Plus 11 other moderates against next/postcss/lodash transitives;
  all resolved by the bumps above. Run `pnpm audit --audit-level=moderate
  --prod` after bumps; expectation is zero.

#### M-2. `pnpm.overrides` not configured
- Root package.json has no `pnpm.overrides` block. For a security
  product where transitive CVEs land regularly (multer, lodash) and
  upstream isn't always fast, having an `overrides` mechanism ready
  is hygiene. Add an empty `pnpm.overrides: {}` and document its use
  in the operator runbook.

#### M-3. Postinstall scripts are not globally disabled
- `pnpm config get ignore-scripts` returns `undefined` (= default
  `false`, i.e. scripts run). `.npmrc` does not set `ignore-scripts`.
- Postinstall scripts present in the current tree (enumerated):
  - `esbuild@0.18.20`: `node install.js` — fetches platform binary.
  - `esbuild@0.19.12`: `node install.js` — same.
  - `unrs-resolver@1.11.1`: `napi-postinstall unrs-resolver 1.11.1 check`
    — N-API platform-binary check, transitive via `eslint-plugin-import`.
  - `sharp@0.33.5`: `install` script `node install/check` — fetches
    libvips binary; transitive via Next.js image optimization.
- All four are well-known mainstream packages with legitimate
  reasons to run install scripts (fetching native/platform-specific
  binaries). None are unexpected. **However**, for a vault product
  the supply-chain blast radius from any single one of these being
  compromised (cf. event-stream, ua-parser-js incidents) is total.
- Recommendation (medium, applied in Phase 02 hardening, info now):
  Set `ignore-scripts=true` in `.npmrc`, then explicitly allow the
  small set above with pnpm's `onlyBuiltDependencies` field in root
  package.json:
  ```json
  "pnpm": {
    "onlyBuiltDependencies": ["esbuild", "sharp", "unrs-resolver"]
  }
  ```
  This converts an open-by-default trust model into an
  enumerated-allowlist trust model.

#### M-4. Dependency tree size (~726 unique resolved packages in store)
- Not anomalous for a Nest+Next monorepo, but on the heavy side.
  Nothing actionable today; flag for periodic review.

### Low

#### L-1. `engines.pnpm` in root package.json is `>=9.0.0`, not pinned
- `packageManager` is correctly pinned to `pnpm@9.15.0`, but
  `engines.pnpm` is permissive (`>=9.0.0`). Tighten to `>=9.15.0`
  for consistency with `packageManager`.

#### L-2. `eslint-config-next` is pinned to `15.1.0` (exact)
- This will block the Next bump unless updated together. Acceptable;
  document the linkage.

#### L-3. `react`, `react-dom`, `next` use exact (no caret) pins
- Web app uses `"next": "15.1.0"`, `"react": "19.0.0"`, etc. Exact
  pins are stricter than required and harmless, but they require
  explicit dependabot/manual bumps for security patches. Dependabot
  config does cover this. Note: this is the *opposite* of the typical
  posture (caret) — flagging only as awareness, not as a defect.

### Info

#### I-1. Workspace protocol consistency — clean
All `@simplevault/*` deps in apps/* and packages/* use `workspace:*`.
None resolve to npm registry; `pnpm list -r` shows
`link:../../packages/*` for every cross-package edge. No risk of a
typosquat hijacking an internal dep name on npm.

#### I-2. Typosquat scan — clean
Top-level deps reviewed: `@nestjs/*`, `next`, `react`, `react-dom`,
`drizzle-orm`, `drizzle-kit`, `pg`, `ioredis`, `helmet`, `pino`,
`pino-http`, `nestjs-pino`, `class-validator`, `class-transformer`,
`reflect-metadata`, `rxjs`, `zod`, `libsodium-wrappers-sumo`,
`@noble/hashes`, `bip39`, `tailwindcss`, `autoprefixer`, `postcss`,
turbo/typescript/eslint/prettier. All are canonical, widely-used
packages. No typosquat patterns detected (no `expresss`,
`nestjs-helmet`, `react-router-domm`, etc.).

#### I-3. Production vs dev separation — clean
- `apps/api`: TypeScript, ESLint, ts-node, @types/*, NestJS CLI all
  in `devDependencies`. Production deps are runtime only.
- `apps/web`: TypeScript, ESLint, autoprefixer, postcss, tailwindcss,
  @types/* all in `devDependencies`. Production is just `next`,
  `react`, `react-dom`, and `@simplevault/shared`.
- Recommend Dockerfiles use `pnpm deploy --filter <app> --prod` (or
  equivalent) to emit production-only node_modules. Verify in the
  infra-deployment auditor's report; cross-link.

#### I-4. Lockfile integrity — clean
- `pnpm-lock.yaml` is committed (`git ls-files` confirms),
  `lockfileVersion: '9.0'` (current for pnpm 9).
- `pnpm install --frozen-lockfile` exits 0; no drift between any
  package.json and the lockfile.

#### I-5. .npmrc settings — clean
- `strict-peer-dependencies=true` ✔
- `auto-install-peers=false` ✔
- `shared-workspace-lockfile=true` ✔ (single source of truth)
- `shamefully-hoist=false` ✔ (no phantom deps)
- `node-linker=isolated` ✔ (best isolation, prevents
  cross-package phantom imports)
- Missing: `ignore-scripts=true` (see M-3).

#### I-6. .nvmrc, engines — clean
- `.nvmrc` = `22`, `engines.node` = `>=22.0.0`. Matches modern LTS;
  consistent with Dockerfiles per infra audit scope.

#### I-7. Dependabot — clean
- `.github/dependabot.yml` covers npm (root with workspace
  auto-detection via pnpm-workspace.yaml), github-actions, and docker
  for both apps. Weekly schedule, sensible PR cap (10), groups for
  nest/next/drizzle/typescript/eslint clusters. Good config.

---

## Recommendations

### Must-fix to clear the gate (Critical/High)
1. **Bump `next` to `>=15.5.15`** in apps/web (clears C-1, C-2, H-1, H-7
   plus several moderates). Update `eslint-config-next` to a matching
   version.
2. **Bump `drizzle-orm` to `^0.45.2`** (and `drizzle-kit` to a
   compatible version) in packages/db (clears H-6). Re-run
   `pnpm db:generate` and verify schema output is unchanged.
3. **Resolve multer transitive (clears H-2..H-4)** by either:
   - upgrading `@nestjs/*` from `^10.x` to `^11.x` (also clears the
     M-1 `@nestjs/core` moderate), OR
   - adding `pnpm.overrides` entry: `"multer": ">=2.1.1"` until ready
     to do the Nest major bump.
4. Re-run `pnpm audit --audit-level=high --prod` and confirm zero
   findings before merging Phase 01.

### Should-fix in Phase 02 hardening (Medium)
5. Adopt `ignore-scripts=true` + `onlyBuiltDependencies` allowlist
   (M-3). This is the single highest-leverage supply-chain hardening
   step for a vault product.
6. Add empty `pnpm.overrides` block to root package.json with a
   comment explaining when to use it (M-2).
7. Document the lodash@4.17.21 advisory (H-5) in the operator runbook
   as an accepted-with-justification residual risk pending upstream
   release.

### Nice-to-have (Low)
8. Tighten `engines.pnpm` to `>=9.15.0` (L-1).
9. Consider switching `next`/`react`/`react-dom` to caret ranges to
   pick up patches automatically via dependabot (L-3) — or keep exact
   and rely on the existing dependabot grouping.

---

## Verdict

**FAIL.** Two Critical and seven High CVEs in production-affecting
dependencies block Phase 01 merge. All are upstream-fixed (except
H-5 lodash, accepted residual). Apply the three bumps in the
"must-fix" list, re-run `pnpm audit --audit-level=high --prod` until
clean, and the gate flips to PASS. Estimated developer time to clear:
under one hour, plus regression testing of any drizzle schema changes
from the orm bump.
