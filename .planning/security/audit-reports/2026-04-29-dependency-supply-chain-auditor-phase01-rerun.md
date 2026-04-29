---
Date: 2026-04-29
Auditor: dependency-supply-chain-auditor
Scope: Phase 01 RE-RUN — verify closure of FINDING-0001..0004 from
       the 2026-04-28 dependency-supply-chain audit, plus regression
       sweep of the bumped dependency surface.
Method: Read-only inspection of repo + `pnpm install --frozen-lockfile`
        + `pnpm audit --audit-level=high --prod`
        + `pnpm audit --audit-level=high` (incl dev)
        + lockfile grep for resolved versions of next, drizzle-orm,
          drizzle-kit, multer, lodash
        + `pnpm why` / `pnpm list -r` for transitive paths
        + `pnpm view lodash versions` for upstream patch availability
Verdict: PASS-WITH-CONCERNS — all four blocking findings closed.
         One residual (lodash via @nestjs/config) is now PATCHABLE
         upstream (lodash >=4.18.0 exists) and is re-classified as a
         NEW high finding requiring a `pnpm.overrides` pin or
         dependency upgrade. Three additional dev-only High advisories
         (glob CLI, picomatch ReDoS — both via @nestjs/cli) are noted
         as non-blocking dev-tree concerns.
Previous-run reference:
  .planning/security/audit-reports/2026-04-28-dependency-supply-chain-auditor-phase01.md
---

# Dependency Supply-Chain Audit — Phase 01 RE-RUN

## Summary

The four blocking findings raised on 2026-04-28
(FINDING-0001 next RCE, FINDING-0002 next auth-bypass,
FINDING-0003 drizzle-orm SQL-injection, FINDING-0004 multer 3x DoS)
are all **VERIFIED CLOSED** in the lockfile. `pnpm install
--frozen-lockfile` exits 0. No lockfile drift.

The 2 Criticals from the prior run are gone. No new Criticals.
No new prod High advisories were introduced by the bumps to
`next@15.5.15`, `drizzle-orm@0.45.2`, `drizzle-kit@0.31.10`, or
the `multer@>=2.1.1` override.

One residual carried over from the previous run, **lodash@4.17.21
via `@nestjs/config@3.3.0`**, has materially changed status: GitHub
advisory GHSA-r5fr-rjxr-66jc now lists `>=4.18.0` as the patched
range, and `lodash@4.18.0`/`4.18.1` are published on npm and already
resolved elsewhere in this workspace (the dev tree pulls 4.18.1).
On the 2026-04-28 run this was accepted as residual because no
upstream patch existed; today a patch exists, so per the brief I am
re-classifying this as a **NEW High finding** that warrants either a
`pnpm.overrides` pin (`lodash@<4.18.0` -> `>=4.18.1`) or upgrading
`@nestjs/config` once a release ships pulling the patched range.

Verdict: **PASS-WITH-CONCERNS**. The phase-blocking ceiling
(Critical + prod-High that gates a phase per the GSD security
contract) is clear. The lodash advisory is High but transitive,
exploitation requires `_.template` invocation on attacker-controlled
key names which is not present in any first-party code path, and a
clean fix exists. Recommend closing it before Phase 02 lands but it
does not need to block Phase 01 sign-off if the operator accepts the
risk and tracks it.

---

## Re-verification of FINDING-0001..0004 closure

All package-version checks were done against the committed
`pnpm-lock.yaml` (the source of truth `--frozen-lockfile` resolves
from), cross-checked against the manifest entries.

### FINDING-0001 — next RCE (GHSA-9qr9-h5gf-34mp) — VERIFIED CLOSED
- Manifest: `apps/web/package.json` line 15 → `"next": "^15.5.15"`
- Lockfile: `pnpm-lock.yaml` line 2923 → `next@15.5.15:`
- Lockfile snapshot line 6535 →
  `next@15.5.15(react-dom@19.0.0(react@19.0.0))(react@19.0.0):`
- Vulnerable range was `>=15.1.0-canary.0 <15.1.9`. 15.5.15 is well
  past the patch. The advisory does not reappear in
  `pnpm audit --prod` output.

### FINDING-0002 — next middleware auth-bypass (GHSA-f82v-jwr5-mffw) — VERIFIED CLOSED
- Same `next@15.5.15` install as FINDING-0001.
- Vulnerable range was `>=15.0.0 <15.2.3`. 15.5.15 is patched.
- CSP middleware kept intact: `apps/web/src/middleware.ts:19`
  still emits `Content-Security-Policy` header (post-bump build
  spot-checked — middleware compiled output present in
  `apps/web/.next/server/src/middleware.js`).
- The advisory does not reappear in `pnpm audit --prod`.

### FINDING-0003 — drizzle-orm SQL-injection — VERIFIED CLOSED
- Manifests:
  - `packages/db/package.json` line 22 → `"drizzle-orm": "^0.45.2"`
  - `packages/db/package.json` line 26 → `"drizzle-kit": "^0.31.10"`
  - `apps/api` consumes drizzle-orm only transitively via
    `@simplevault/db` workspace dep — no direct drizzle pin in
    `apps/api/package.json`, so the workspace dep correctly
    governs the version.
- Lockfile: `pnpm-lock.yaml` line 1943 → `drizzle-orm@0.45.2:`,
  line 5399 → `drizzle-orm@0.45.2(@types/pg@8.20.0)(pg@8.20.0):`
  (single hoisted version — no duplicate older copy).
- `drizzle-kit@0.31.10` resolved at lockfile line 1939 / 5392.
- The SQL-injection advisory does not reappear in
  `pnpm audit --prod`.

### FINDING-0004 — multer ≥3 DoS CVEs — VERIFIED CLOSED
- Override block in root `package.json` lines 26-30:
  ```
  "pnpm": {
    "overrides": {
      "multer@<2.1.1": ">=2.1.1"
    }
  }
  ```
- Lockfile honors the override:
  - line 8 → `multer@<2.1.1: '>=2.1.1'` (override declaration block)
  - line 2880 → `multer@2.1.1:` (single resolved version)
  - line 6501 → `multer@2.1.1:` (snapshot)
  - line 4477 → consumed by `@nestjs/platform-express@10.4.x`:
    `multer: 2.1.1`
- `pnpm list multer -r` shows a single version: `multer 2.1.1`
  (no other resolutions present; previous transitive 2.0.2 is gone).
- None of the three multer DoS advisories appears in
  `pnpm audit --prod`.

---

## Full `pnpm audit --audit-level=high --prod` output (sanitized)

```
┌─────────────────────┬────────────────────────────────────────────────────────┐
│ high                │ lodash vulnerable to Code Injection via `_.template`   │
│                     │ imports key names                                      │
├─────────────────────┼────────────────────────────────────────────────────────┤
│ Package             │ lodash                                                 │
├─────────────────────┼────────────────────────────────────────────────────────┤
│ Vulnerable versions │ >=4.0.0 <=4.17.23                                      │
├─────────────────────┼────────────────────────────────────────────────────────┤
│ Patched versions    │ >=4.18.0                                               │
├─────────────────────┼────────────────────────────────────────────────────────┤
│ Paths               │ apps/api > @nestjs/config@3.3.0 > lodash@4.17.21       │
├─────────────────────┼────────────────────────────────────────────────────────┤
│ More info           │ https://github.com/advisories/GHSA-r5fr-rjxr-66jc      │
└─────────────────────┴────────────────────────────────────────────────────────┘
7 vulnerabilities found
Severity: 6 moderate | 1 high
```

- Process exit code: 0 (audit-level threshold is `high`; the 6
  moderate items are below threshold).
- Critical count in prod tree: **0** (was 2).
- High count in prod tree: **1** (was 7), and that 1 is the lodash
  carry-over.
- The 6 moderate prod findings are unchanged in shape from the
  previous run's moderate bucket and are not in scope for this
  high+ re-audit (carrying over as documented residuals).

---

## Full `pnpm audit --audit-level=high` (incl dev) output

```
┌─────────────────────┬────────────────────────────────────────────────────────┐
│ high                │ glob CLI: Command injection via -c/--cmd executes      │
│                     │ matches with shell:true                                │
│ Package             │ glob                                                   │
│ Vulnerable versions │ >=10.2.0 <10.5.0                                       │
│ Patched versions    │ >=10.5.0                                               │
│ Paths               │ apps/api > @nestjs/cli@10.4.9 > glob@10.4.5            │
│ More info           │ https://github.com/advisories/GHSA-5j98-mcp5-4vw2      │
└─────────────────────┴────────────────────────────────────────────────────────┘
┌─────────────────────┬────────────────────────────────────────────────────────┐
│ high                │ Picomatch has a ReDoS vulnerability via extglob        │
│                     │ quantifiers                                            │
│ Package             │ picomatch                                              │
│ Vulnerable versions │ >=4.0.0 <4.0.4                                         │
│ Patched versions    │ >=4.0.4                                                │
│ Paths               │ apps/api > @nestjs/cli@10.4.9 >                        │
│                     │ @angular-devkit/core@17.3.11 > picomatch@4.0.1         │
│                     │ ... 8 paths total via @nestjs/cli                      │
│ More info           │ https://github.com/advisories/GHSA-c2c7-rcm5-vvqj      │
└─────────────────────┴────────────────────────────────────────────────────────┘
┌─────────────────────┬────────────────────────────────────────────────────────┐
│ high                │ lodash vulnerable to Code Injection via `_.template`   │
│ Package             │ lodash                                                 │
│ Vulnerable versions │ >=4.0.0 <=4.17.23                                      │
│ Patched versions    │ >=4.18.0                                               │
│ Paths               │ apps/api > @nestjs/config@3.3.0 > lodash@4.17.21       │
│ More info           │ https://github.com/advisories/GHSA-r5fr-rjxr-66jc      │
└─────────────────────┴────────────────────────────────────────────────────────┘
15 vulnerabilities found
Severity: 3 low | 9 moderate | 3 high
```

- Process exit code: 0.
- Two additional High advisories appear in the dev-only tree, both
  rooted at `@nestjs/cli@10.4.9`:
  1. `glob@10.4.5` — command injection via `glob -c/--cmd`.
     Reachable only if a developer (or a CI hook) runs the `glob`
     CLI binary with `-c` against attacker-controlled match
     patterns. Not invoked anywhere in repo scripts. Patched in
     `glob@10.5.0`; pulled by `@nestjs/cli@10.4.9`.
  2. `picomatch@4.0.1` — ReDoS via extglob quantifiers.
     Reachable only via the `@angular-devkit/*` schematic CLI tools
     that `@nestjs/cli` ships with; risk is a developer hanging a
     local Nest schematic invocation on a malicious extglob pattern.
     Patched in `picomatch@4.0.4`.
- Both will likely be cleared by the same Phase 02 NestJS-11 upgrade
  that retires the multer override (NestJS 11 ships a refreshed
  `@nestjs/cli` line). They are non-blocking for Phase 01 because
  they are dev-only and not invoked by build/test/CI scripts (root
  `turbo.json` and per-app `scripts` blocks don't run `nest schematic`
  or `glob -c`).

---

## New findings (delta vs. 2026-04-28 run)

### NEW-1 (High, prod) — lodash patch is now available upstream → re-classified
- Advisory: GHSA-r5fr-rjxr-66jc
- Package path: `apps/api > @nestjs/config@3.3.0 > lodash@4.17.21`
- Status change: On 2026-04-28 the advisory had no patched range
  reachable — it was accepted as carried-over residual. Today the
  advisory lists `Patched versions: >=4.18.0`, and `pnpm view lodash
  versions` confirms 4.18.0 and 4.18.1 are published. The dev tree
  in this same workspace already resolves `lodash@4.18.1` (via
  inquirer / node-emoji), proving npm publishes are intact.
  `@nestjs/config@3.3.0` still pulls 4.17.21, so the advisory still
  reports against the prod tree.
- Recommended fix (one of):
  1. Add a `pnpm.overrides` entry alongside the multer pin:
     `"lodash@<4.18.0": ">=4.18.1"` (one-line, low-risk — lodash 4.x
     is API-stable; the 4.18.x bump is a security-only release).
  2. Wait for `@nestjs/config` to publish a release that pulls the
     patched range and bump the direct dep.
- I recommend option 1 before Phase 02 ships, with a tracked note to
  remove it once `@nestjs/config` upgrades upstream (same lifecycle
  as the multer override — see Override Hygiene below).
- Severity: High (per the advisory). Real-world exploitability in
  this codebase is **low**: `_.template` is not used by
  `@nestjs/config` at runtime (it uses lodash for `get`/`merge`/`has`
  helpers on config objects, not template compilation), and no
  first-party SimpleVault code calls `_.template` either. So the
  attacker would need to find an indirect call site. Still, defense
  in depth + a clean fix exists, so flag it.

### NEW-2 (High, dev-only) — glob CLI command-injection via `@nestjs/cli`
- See dev audit output above. Non-blocking for Phase 01 (dev-only,
  not invoked by repo scripts). Will clear when NestJS 11 lands in
  Phase 02 (NestJS 11's CLI ships with patched glob).

### NEW-3 (High, dev-only) — picomatch ReDoS via `@angular-devkit/*`
- See dev audit output above. Non-blocking for Phase 01 (dev-only,
  reachable only via Nest schematic CLIs that aren't wired into any
  repo script). Same Phase-02-NestJS-11 cleanup as NEW-2.

No new prod Critical advisories. No new prod High advisories beyond
the lodash re-classification.

---

## Carried-over residuals

- **lodash@4.17.21 (prod)** — see NEW-1 above. Now patchable; should
  be addressed but not phase-blocking by itself.
- **6 moderate prod advisories** (unchanged shape vs. 2026-04-28
  run; all transitive, mostly via `@nestjs/cli` legacy deps). Below
  the high+ threshold for this re-audit. Tracked to clear with
  Phase 02 NestJS-11 upgrade.
- **3 low advisories** (dev-only, transitive). Documented for
  completeness.
- **`pnpm.overrides` block** — currently pins `multer@<2.1.1` ->
  `>=2.1.1`. This is a tracked security one-off; see Override
  Hygiene below.

---

## Override hygiene (tech-debt tracker)

The root `package.json` now ships a `pnpm.overrides` block. This is
a deliberate, security-motivated pin and is acceptable for Phase 01,
but it is **tech debt** that should be cleared as soon as upstream
publishes a clean dependency tree:

- **`multer@<2.1.1` -> `>=2.1.1`** (added 2026-04-28, commit
  `71c6399`)
  - Trigger to remove: NestJS 11 upgrade (Phase 02). NestJS 11's
    `@nestjs/platform-express` pulls `multer@^2.1.x` directly, which
    will make the override redundant.
  - When removing: also delete the `pnpm.overrides` block entirely
    if no other entries remain, then re-run `pnpm install` and
    confirm the lockfile resolves multer ≥2.1.1 organically.

- **(recommended add) `lodash@<4.18.0` -> `>=4.18.1`**
  - Trigger to remove: `@nestjs/config` publishes a release that
    pulls `lodash@^4.18.0` directly, OR the NestJS 11 upgrade in
    Phase 02 brings `@nestjs/config@4.x` which already does so.

A `# TODO(phase-02): remove multer/lodash overrides once
@nestjs/platform-express + @nestjs/config pull patched ranges
directly` comment at the top of the `pnpm.overrides` block is
recommended so this isn't forgotten when Phase 02 lands.

---

## Lockfile sanity

```
$ pnpm install --frozen-lockfile
Scope: all 8 workspace projects
Lockfile is up to date, resolution step is skipped
Already up to date

Done in 1.9s
```

Exit 0. No drift.

---

## Verdict

**PASS-WITH-CONCERNS.**

- All four phase-blocking findings (FINDING-0001, -0002, -0003,
  -0004) are **VERIFIED CLOSED** in the lockfile and confirmed by
  re-running `pnpm audit --prod`.
- The 2 Criticals are gone. No new Criticals.
- No new prod High advisories were introduced by the version bumps.
- One residual (lodash via `@nestjs/config`) is **re-classified** as
  a NEW high finding because an upstream patch (`>=4.18.0`) now
  exists where on 2026-04-28 it did not. Recommended fix is a
  one-line `pnpm.overrides` addition. Real-world exploitability in
  this codebase is low; recommend closing before Phase 02 but it
  does not by itself block Phase 01 sign-off if the operator
  acknowledges and tracks it.
- Two dev-only High advisories (glob CLI, picomatch ReDoS) are
  inherited from `@nestjs/cli@10.4.9` and will clear with the
  Phase 02 NestJS 11 upgrade. Non-blocking for Phase 01.
- The `pnpm.overrides` block is correct and effective; it is logged
  as tracked tech debt to remove when NestJS 11 lands.
