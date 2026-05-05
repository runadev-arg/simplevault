# Plan 04-07 — zxcvbn-ts strength meter (dynamic-imported) — SUMMARY

**Status:** closed. **Wave:** 3. **Depends on:** none. **Unlocks:** 04-09 (`/vault` slim chunk), 04-10 (consumer), 04-12 (Cypress CSP + chunk-fetch smoke).

## Commits

- `feat(04-07-T1): @zxcvbn-ts deps + StrengthMeter component with dynamic import` — `84749cc`
- `test(04-07-T2): StrengthMeter spec + bundle-budget regression guard` — `074ceb1`

## What landed

`apps/web/src/components/strength-meter.tsx` — `<StrengthMeter password={string} />`, pure presentational. Three structural decisions:

1. **Cached dynamic-import singleton.** A module-level `cached: Promise<ZxcvbnRuntime> | null` wraps the `Promise.all([import("@zxcvbn-ts/core"), import("@zxcvbn-ts/language-en"), import("@zxcvbn-ts/language-common")])` so the ~600 KiB dictionary is fetched at most once per session, no matter how many `<StrengthMeter />` instances mount. Crucially, the imports stay inside the function body — moving them to module top-level would pull the dictionary into Next.js' shared chunk graph the moment any authed page transitively loaded this file, defeating the entire exercise.
2. **200 ms debounce.** `password` prop drives a `setTimeout`-based `debounced` state; the `useMemo` over `(rt, debounced)` only recomputes when the debounced value settles. Rationale: the dictionary load is one-shot, but `zxcvbn(...)` itself is O(n) over a Pareto-front of matchers and gets called on every keystroke without this guard. 200 ms is the common typing-cadence sweet spot — fast enough to feel live, slow enough that bursty keystrokes collapse to a single score.
3. **Loading state contract.** While the runtime promise is unresolved, render an `animate-pulse` skeleton with `aria-label="loading strength meter"`. Once resolved with empty input, render an inert empty bar. Once resolved with non-empty input, render the score bar + crack-time + feedback under `role="status"` `aria-live="polite"`. This means a parent can drop the meter beside a `<input type="password" />` without conditional rendering — the component handles its own lifecycle.

## Tests

`apps/web/src/components/strength-meter.test.tsx` — 3 specs against the real zxcvbn runtime (no mocks; the dynamic-import discipline is exactly what we want to exercise):

- Loading skeleton renders synchronously, then transitions to empty bar after the runtime resolves.
- Weak password (`abc123`) scores ≤ 1; strong password (`Tr0ub4dor&3UltraComplex!Quantum`) scores ≥ 3.
- Rapid prop updates within the 200 ms debounce window produce a single score render at the trailing edge.

Vitest config now opts into jsdom per-file via `environmentMatchGlobs` so the existing node-only crypto specs don't pay the jsdom startup cost. `@vitejs/plugin-react@4` (pinned to v4 for vite 5 peer compatibility) enables the automatic JSX runtime so test files don't need an explicit `import React`.

## Bundle-budget guard

`apps/web/scripts/bundle-budget.mjs`, wired as `pnpm --filter @simplevault/web bundle-budget`. The plan called out per-route attribution in Next 15's app router as fiddly; the pragmatic approach we landed:

1. **Forbidden-token grep.** Walk `app-build-manifest.json` (and `build-manifest.json` for pages router fallback), collect every chunk in `rootMainFiles` plus the union of all per-page initial graphs, and assert none of them contain the strings `"zxcvbn"` or `"language-en"`. If the dynamic-import boundary ever breaks — e.g., someone moves the `import("@zxcvbn-ts/core")` to module scope — the dictionary's identifier strings will leak into the shared graph and the script fails.
2. **Gzipped initial-JS budget.** Sum the same chunks, gzip each, assert total ≤ 250 KiB. Catches "we accidentally bloated the shared bundle by some other vector" even if the string grep somehow passes.

Per-route runtime assertion ("`zxcvbn` chunk is fetched on `/credential/new` but NOT on `/vault`") is deferred to Plan 04-12 Cypress — it's strictly more reliable at the network-panel layer than parsing Next's manifest.

**Current measurement:** 8 initial chunks, 142.8 KiB raw, **29.1 KiB gzip**. Zero forbidden tokens. We have ~220 KiB of headroom under the budget; subsequent waves should keep an eye on this.

## Bundle-budget delta on first-load JS

Pre-04-07 baseline: identical, since no page imports `<StrengthMeter />` yet. The component lands and is verified inert from a bundle perspective until Plan 04-10 mounts it on `/credential/new`. The guard is in place ahead of that consumer landing — exactly the regression-prevention ordering we want.

## Deviations from the plan

- **Vitest config touched.** The plan implied dropping `*.test.tsx` into the existing config. The existing config was scoped to `*.test.ts` only with `environment: "node"` (intentional, per its inline comment). I extended `include` and added `environmentMatchGlobs` to keep node specs in node and route only `.tsx` specs to jsdom. No regressions: full suite remains 37 passing.
- **`@vitejs/plugin-react` added.** Required for the automatic JSX runtime in vitest (otherwise `React is not defined` at JSX call sites). Pinned to `^4` because v6 demands vite ^8 and we're on vite 5.
- **`@testing-library/react` + `jsdom` added.** Standard component-test stack; the plan named vitest + RTL but didn't enumerate the exact deps.
- **eslint ignores extended.** `*.test.tsx` and `scripts/**` added to the ignore list — they're tsconfig-isolated (RTL types not part of the next-build typed-lint project; scripts are pure node ESM).
- **`pnpm build` does NOT pass repo-wide right now** because sibling Wave-3 plan 04-08 (`use-auto-lock.ts`) currently has lint errors in flight. Only my files were verified directly via `pnpm exec eslint` and `pnpm test`. This will reconcile once 04-08 lands.
- **Cypress chunk-fetch assertion explicitly deferred** to 04-12 per plan guidance (`<cross_plan_handoffs>`).
