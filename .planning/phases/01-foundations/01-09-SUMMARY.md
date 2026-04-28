# Plan 01-09 — GitHub Actions CI Pipeline — SUMMARY

**Status:** COMPLETE
**Date:** 2026-04-28
**Commits:** 2 atomic commits + 1 docs commit

## What was delivered

Four files under `.github/`:

1. **`.github/workflows/ci.yml`** — main CI workflow. Runs on `push` to `main`, `pull_request` to `main`, and `workflow_dispatch`. Concurrency group cancels in-progress runs on the same ref. `permissions: contents: read` minimal. Steps:
   - StepSecurity `harden-runner` (egress-policy: audit) — supply-chain defense-in-depth.
   - `actions/checkout` (full history).
   - `actions/setup-node` Node 22.
   - `pnpm/action-setup` v4 with version `9.15.0` (matches root `packageManager`). `run_install: false` so we control caching.
   - pnpm store path captured + `actions/cache` keyed on `pnpm-lock.yaml` hash.
   - `pnpm install --frozen-lockfile`.
   - `pnpm lint` → `pnpm typecheck` → `pnpm build` → `pnpm audit --audit-level=high`. No `|| true`. Audit failures fail the job, per plan key_links.
   - `timeout-minutes: 15` (plan target <8 min — should be comfortable once cache is warm).

2. **`.github/workflows/container-scan.yml`** — Trivy CRITICAL+HIGH scan for both production images. Triggers only on PRs touching Dockerfiles, `pnpm-lock.yaml`, or `package.json` files (and on `main` push for Dockerfile changes). Matrix builds `simplevault-api` and `simplevault-web` from repo root via `docker/build-push-action` with `cache-from: type=gha` / `cache-to: type=gha,mode=max`. Trivy `exit-code: 1`, `ignore-unfixed: true`, `format: table`. `fail-fast: false` so one image's findings don't mask the other.

3. **`.github/dependabot.yml`** — weekly Monday updates for npm (root, workspace-aware), GitHub Actions, and Docker (per-app). Grouped: `nest`, `next`, `drizzle`, `typescript`, `eslint`. Limits: 10 npm, 5 actions PRs.

4. **`.github/CODEOWNERS`** — `@germankatz` owns everything. Security-critical paths (`/.planning/security/`, `/packages/crypto/`, `/apps/api/src/auth/`, `/apps/api/src/audit/`) called out explicitly so future-team enforcement is one-line away.

## Pinning policy

Every third-party action pinned by full commit SHA + comment with the `vN.N.N` tag, exactly as plan specified. SHAs used (no deviations from spec):

- `step-security/harden-runner@0080882f6c36860b6ba35c610c98ce87d4e2f26f` # v2.10.2
- `actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11` # v4.1.1
- `actions/setup-node@1e60f620b9541d16bece96c5465dc8ee9832be0b` # v4.0.3
- `pnpm/action-setup@fe02b34f77f8bc703788d5817da081398fad5dd2` # v4.0.0
- `actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9` # v4.0.2
- `docker/setup-buildx-action@988b5a0280414f521da01fcc63a27aeeb4b104db` # v3.6.1
- `docker/build-push-action@5cd11c3a4ced054e52742c5fd54dca954e0edd85` # v6.7.0
- `aquasecurity/trivy-action@18f2510ee396bbf400402947b394f2dd8c87dbb0` # v0.27.0

## Verification

- Both workflow YAMLs and dependabot.yml parse as valid YAML (validated via Ruby's `YAML.load_file`; `actionlint` not installed locally).
- All carry-over rules respected: pnpm version pinned matches root `packageManager` (9.15.0); Node version matches `.nvmrc` (22); Docker build context is repo root; we do NOT install pnpm via `setup-node`'s packageManager arm (we use the dedicated `pnpm/action-setup`).
- No actual workflow run executed — workflows will exercise on the next push to a branch / PR. Run-time observations and audit findings will be added on the first live run.

## Deviations from plan

None. Spec executed verbatim.

## Notes / handoff

- `pnpm audit --audit-level=high` is the moment of truth for dependency choices made in Plans 01–06. Expectation: zero High+ findings; if anything surfaces on first run, address before merging Plan 10.
- `pnpm/action-setup@v4` historically had a chicken-and-egg with `setup-node`'s built-in pnpm cache — we side-stepped this by running `setup-node` first WITHOUT `cache: 'pnpm'` and managing the store cache ourselves via `actions/cache`. This matches the carry-over guidance.
- Container-scan workflow does NOT push images — it loads them locally (`load: true`) and scans in place. Phase 14 will add a separate publish workflow.
- Phase 02+ will add a `postgres` service to `ci.yml` once integration tests exist.
- Plan 07 (docker-compose) is unblocked. Plan 08 (migrations) will likely want a small DB-bringup job in CI later — not in scope here.

## Commits

- `b9e11a2` — `ci(01-09-T1): main CI workflow (lint, typecheck, build, audit)`
- `129136c` — `ci(01-09-T2): container scan workflow + Dependabot + CODEOWNERS`
- (this) — `docs(01-09): complete GitHub Actions CI pipeline`
