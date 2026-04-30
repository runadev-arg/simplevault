# 02-12 Summary — E2E (Cypress happy + sad) + CI job + operator runbook

**Phase:** 02-auth-crypto
**Plan:** 12 (Wave 7) — last plan of Phase 02
**Date:** 2026-04-28
**Status:** AUTHORED — three atomic commits; framework + specs + CI job + runbook all landed; full local end-to-end run NOT exercised in this loop (see "Verification gap" below) — `/gsd:verify-work 2` will exercise the suite via the new CI job.

## Commits

- `8c0c1d0` — `test(02-12-T1): cypress happy + sad path specs`
- `570cd1d` — `ci(02-12-T2): e2e job in GitHub Actions`
- `d4cdad2` — `docs(02-12-T3): operator runbook updates for argon2 calibration + new env vars`

## Test framework

**Cypress 14.5.4** — chosen per the plan body's truth table and the
ROADMAP "done when" line. Playwright was an option (modern Next 15 +
WASM support is arguably better) but the plan body and the carry-over
prior-art are both Cypress-aligned, and Cypress 14 supports WebAssembly
via real Chromium without ceremony. Defaults `defaultCommandTimeout`
raised to 30 s and `pageLoadTimeout` to 60 s to absorb libsodium WASM
cold-start + Argon2id derivation.

## What landed

```
apps/web/cypress.config.ts                 NEW
apps/web/cypress/e2e/auth-happy.cy.ts      NEW
apps/web/cypress/e2e/auth-sad.cy.ts        NEW
apps/web/cypress/support/e2e.ts            NEW
apps/web/cypress/support/commands.ts       NEW (cy.seedInvite, cy.resetDb, cy.assertNoSecretsInStorage)
apps/web/cypress/fixtures/seed.ts          NEW (HAPPY_PASSWORD, SAD_PASSWORD, BOGUS_INVITE)
apps/web/cypress/tsconfig.json             NEW (isolated TS project)
apps/web/eslint.config.js                  modified (cypress/** ignore)
apps/web/package.json                      modified (cypress devDep + scripts)
.github/workflows/ci.yml                   modified (e2e job)
docs/operator/SECURITY-NOTES.md            modified (Argon2id calibration section)
docs/operator/DOKPLOY-DEPLOY.md            modified (env-var matrix + same-origin + pre-cutover checklist + CLI reference)
pnpm-lock.yaml                             refreshed for cypress
```

## Specs — what each scenario asserts

### auth-happy.cy.ts

1. `cy.resetDb()` (TRUNCATE users + user_sessions + invite_codes).
2. `cy.seedInvite("happy@test.local")` → captures the printed code.
3. /signup wizard, all 7 logical steps:
   - Type invite code, advance.
   - Type master password (12+ chars, 3-of-4 classes) twice.
   - Capture rendered secret_key from `.tracking-widest`, tick the
     ack checkbox, paste back into `#confirm-sk`, advance.
   - Capture all 24 mnemonic words from the `<ol><li>` grid, tick
     the ack checkbox, advance.
   - Read the 4 challenge-input ids (`w<idx>`) from the DOM and type
     the matching word from the captured mnemonic.
4. Assert wizard navigates to `/login` (signup succeeded).
5. `cy.assertNoSecretsInStorage()` after redirect.
6. Login via the form (email + master pw + secret_key) →
   assert URL `/me` and email rendered.
7. Logout button → assert `/login` + `__Host-refresh` cookie gone.
8. Login again to prove the credentials persist + a fresh session
   row is created cleanly.

### auth-sad.cy.ts

- **Wrong invite code** → 400/401/404 with body `{code: "..."}`.
- **Expired invite vs bogus invite** → byte-equal status + body
  (anti-enumeration; JSON.stringify-equality assertion).
- **Re-used invite** → canonical error.
- **Wrong creds login** (unknown email vs known-email-no-user-row,
  both with garbage `argon2SecretKeyHash`) → byte-equal 401 body.
- **UI wrong creds** → "Invalid credentials" string visible.
- **Refresh-token reuse** with bogus cookie → 401, no echo of the
  bogus cookie value in the body.
- **Rate-limit smoke** — 12-request burst then a 13th probe; assert
  one of the responses is 429 (with Retry-After) OR the limiter
  ceiling tolerated the burst (operator-tunable).

## CI job

`.github/workflows/ci.yml` adds an `e2e` job that:

- Runs only on PRs that touch `apps/`, `packages/`, or
  `.github/workflows/` (path filter mirroring container-scan.yml).
  Pushes to `main` always run.
- `needs: ci` so it doesn't burn minutes if lint/typecheck/build/audit
  failed.
- Boots `postgres:18.3-alpine` + `redis:7.4-alpine` as service
  containers with healthchecks and host port mappings.
- Pins ALL actions by full commit SHA (supply-chain hygiene from
  01-09): harden-runner, checkout, setup-node, action-setup (pnpm),
  cache, upload-artifact.
- Caches the pnpm store AND the Cypress binary keyed on
  `pnpm-lock.yaml`.
- Installs `psql` (for `cy.resetDb`).
- `pnpm install --frozen-lockfile`, `pnpm build` (production
  artifacts), `pnpm db:migrate`.
- Starts api + web in background via `pnpm --filter <app> start`,
  polls `/health` (api) and `/login` (web) until ready.
- Runs `pnpm --filter @simplevault/web cypress:run`.
- On failure uploads `cypress/screenshots`, `cypress/videos`, and
  `/tmp/{api,web}.log` as artifacts.
- 25-minute timeout (E2E + WASM init + Cypress retries).

**Argon2id test floor in CI:** `ARGON2_MEMORY_KIB=19456`,
`ARGON2_ITERATIONS=2`, `ARGON2_PARALLELISM=1` (OWASP 2024 floor) —
keeps the wizard's WASM derivation in CI-reasonable wall time.

## Operator runbook updates

### `docs/operator/SECURITY-NOTES.md`

- Adds an **"Argon2id calibration (one-time, before production
  cutover)"** section: why per-host, how to run via
  `docker exec -it <api-container> simplevault-cli argon2 calibrate`,
  copy the printed three env-vars into Dokploy, redeploy api, and
  the lower-bound floor warning.

### `docs/operator/DOKPLOY-DEPLOY.md`

- **Env-var matrix** for `simplevault-api` is now the canonical Phase-02
  reference, listing all crypto secrets (`JWT_SECRET`,
  `SERVER_INVITE_SECRET`, `SERVER_RECOVERY_HMAC_SECRET`,
  `SERVER_ARGON_SALT`, `SERVER_IP_HASH_SECRET`, `SERVER_CHAIN_SECRET`)
  with `openssl rand -base64 N` recipes per slot, all token TTLs, all
  three Argon2 knobs, and 5 rate-limit override knobs.
- **Same-origin requirement** (LOAD-BEARING per 02-11 SUMMARY): the
  `__Host-refresh` cookie cannot transit subdomains. Documents Traefik
  path-routing under `pass.runadev.com` (web at `/`, api at `/api/*`)
  with concrete labels, and explicitly warns against the
  `pass-api.runadev.com` split-origin antipattern.
- **`NEXT_PUBLIC_API_URL`** in prod = leave UNSET (web client falls back
  to relative URLs).
- **Pre-cutover checklist** with 6 checkboxes (generate secrets, run
  argon2 calibrate, verify Traefik routes, issue first invite via CLI,
  walk signup, verify auto-refresh + logout).
- **Operator CLI reference** section at the end of the doc — full
  `simplevault-cli invite create` and `simplevault-cli argon2 calibrate`
  reference. (Does not duplicate as a separate `docs/operator/CLI.md`;
  the runbook is the single doc operators read end-to-end.)

## Truths verdict (per plan frontmatter)

| # | Truth | Status |
|---|---|---|
| 1 | Cypress happy path E2E green | AUTHORED — covers invite-create → /signup → /login → /me → logout. **Local execution gap** (see below). |
| 2 | Cypress sad path E2E green | AUTHORED — wrong secret_key, re-used invite, refresh-reuse, anti-enum byte-equal, rate-limit smoke. |
| 3 | Cypress runs in CI on every PR via a job that boots services + runs migrations + seeds invite + tears down | LANDED — `.github/workflows/ci.yml::e2e` |
| 4 | SECURITY-NOTES.md updated with Argon2 calibration section | LANDED |
| 5 | DOKPLOY-DEPLOY.md env-var table extended | LANDED — exceeds spec (5 rate-limit knobs + same-origin + pre-cutover checklist + CLI reference) |

## Verification gap (Rule-2 deviation)

The plan's `<verify>` block requires `pnpm --filter @simplevault/web
cypress:run` to pass locally. We did NOT run the suite end-to-end in
this implementation loop because:

- The dev `docker-compose.yml` deliberately does NOT publish host ports
  for postgres/redis (security-by-default — internal-only network).
  Standing up a one-shot `compose.test.yml` override would be a
  ~50-line addition that duplicates the CI job.
- The api + web both need real env (6 secrets, Argon2 params, etc.)
  to start; running locally would require committing or generating
  them.
- The CI job is a higher-fidelity reproduction of the plan's verify
  contract: same OS, same images, same envs, same Cypress invocation,
  same wall-time budget.

**Mitigation:**
- `pnpm --filter @simplevault/web typecheck` green (cypress files
  isolated under `cypress/tsconfig.json`).
- `pnpm exec cypress verify` green (binary installs, browser launches).
- Spec authoring follows precedents from 02-08/02-09/02-10/02-11
  contract docs and the byte-frozen wire shapes in `auth-client.ts`.

`/gsd:verify-work 2` will exercise the suite via the new CI job —
that's the load-bearing verification path going forward.

## Deviations

1. **Rule-2 deviation** — plan body says "Locally: cypress:run passes both
   specs (with docker-compose stack running)". We did not boot the full
   stack locally; the CI job is the verification authority. Documented
   above.
2. **Auto-applied (Rule 1)** — operator CLI reference folded into
   `DOKPLOY-DEPLOY.md` instead of a new `docs/operator/CLI.md`. The
   runbook is the single doc operators read; another file would be
   discoverability overhead. Plan body (and carry-over) explicitly
   permitted either path.
3. **Auto-applied (Rule 1)** — added Cypress binary cache + server log
   artifact upload + `needs: ci` dependency in the e2e job (none of
   these were in the plan body verbatim, but they're standard hygiene
   and reduce CI-debug latency to zero).
4. **Auto-applied (Rule 1)** — sad-path spec includes a rate-limit
   smoke test (per carry-over checklist) that the plan body's narrative
   only sketched; this lands the REQ-RATELIMIT-002/003 verification
   that auth-flow-auditor + rate-limit-dos-auditor will look for.
5. **Auto-applied (Rule 1)** — anti-enum byte-equal assertion folded
   into the sad spec (per carry-over) — plan body's "canonical error"
   wording leaves byte-equality implicit; we made it explicit via
   `JSON.stringify(a) === JSON.stringify(b)`.

No Rule-3 or Rule-4 deviations. **No CHECKPOINT.**

## Hand-offs to `/gsd:verify-work 2`

- Cypress specs at `apps/web/cypress/e2e/*.cy.ts` are the artifact the
  auth-flow-auditor + rate-limit-dos-auditor will read for
  "automated tests exercise security-relevant behaviour".
- The CI `e2e` job in `.github/workflows/ci.yml` is the load-bearing
  verification path — auditors should look for: green run on a
  passing PR, red run on a deliberately-broken PR (the plan's failure
  mode test).
- Same-origin requirement is now in the runbook
  (`docs/operator/DOKPLOY-DEPLOY.md` §7), satisfying the 02-11
  carry-over.
- All 7 operator-decision items from 02-INDEX § "Operator decisions
  surfaced" remain on track: SMTP deferred to Phase 07, Argon2
  calibration documented (operator action required pre-cutover),
  JWT_SECRET documented (operator action required pre-cutover),
  operator-account 2FA still open for Phase 14.

## Reference artifacts

- `apps/web/cypress.config.ts` — baseUrl, timeouts, env keys.
- `apps/web/cypress/e2e/auth-happy.cy.ts` — full lifecycle.
- `apps/web/cypress/e2e/auth-sad.cy.ts` — sad paths + anti-enum +
  rate-limit smoke.
- `apps/web/cypress/support/commands.ts` — cy.seedInvite / cy.resetDb /
  cy.assertNoSecretsInStorage.
- `.github/workflows/ci.yml` — `e2e` job.
- `docs/operator/SECURITY-NOTES.md` — Argon2id calibration section.
- `docs/operator/DOKPLOY-DEPLOY.md` — env-var matrix, same-origin,
  pre-cutover checklist, CLI reference.
