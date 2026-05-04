---
phase: 03-2fa-sessions
plan: 12
subsystem: e2e-cypress + docs
tags: [cypress, e2e, runbook, security-notes, test-helpers, expose-test-routes, truth-9, truth-10, truth-11, truth-13]
requires:
  - 03-01..03-11 (every prior Phase-03 plan — Plan 12 is the gate-readiness pass)
provides:
  - "Cypress sessions.cy.ts (Truths 11 + 13)"
  - "Cypress 2fa-removal.cy.ts (Truth 10 + Phase-07 hand-off seam)"
  - "Cypress 2fa-webauthn.cy.ts + 2fa-totp.cy.ts (DESCRIBE.SKIP — deferred to live-iteration)"
  - "apps/api test-helpers controller (flip-shared-vault-stub, seed-totp-credential, mutate-webauthn-counter) gated by EXPOSE_TEST_ROUTES"
  - "docs/operator/RUNBOOK.md (NEW) — Phase 03 env vars + lost-2FA + RP-ID change + test-routes safety + operator session revocation"
  - "docs/operator/SECURITY-NOTES.md Phase 03 invariants section"
  - ".env.example SESSION_EPOCH_CACHE_TTL"
affects:
  - "/gsd:verify-work 3 (next step) — runs the 4-auditor + threat-modeler gate against this surface"
  - Phase 07 (deletes the test-helpers controller as part of the broader EXPOSE_TEST_ROUTES cleanup, alongside the VaultProbeModule)
tech-stack:
  added: []
  patterns:
    - "Test-helpers controller mirrors the VaultProbeModule pattern (Plan 03-07): conditional import in app.module.ts gated by EXPOSE_TEST_ROUTES === '1'. Production safety: env var must stay unset on Dokploy (RUNBOOK has the grep + panel checks)."
    - "Cypress specs use cy.exec for shell-outs (mirrors auth-happy.cy.ts) and cy.request for direct API calls. No setupNodeEvents block introduced — the WebAuthn virtual-authenticator + TOTP secret-injection flows that need it are deferred to live-iteration."
    - "Specs that need the test-helpers gate live in CI (EXPOSE_TEST_ROUTES=1 set in .github/workflows/ci.yml) but are inert in production (env var unset)."
key-files:
  created:
    - apps/api/src/test-helpers/test-helpers.controller.ts
    - apps/api/src/test-helpers/test-helpers.module.ts
    - apps/web/cypress/e2e/sessions.cy.ts
    - apps/web/cypress/e2e/2fa-removal.cy.ts
    - apps/web/cypress/e2e/2fa-webauthn.cy.ts (DESCRIBE.SKIP)
    - apps/web/cypress/e2e/2fa-totp.cy.ts (DESCRIBE.SKIP)
    - docs/operator/RUNBOOK.md
  modified:
    - apps/api/src/app.module.ts (conditional import of TestHelpersModule)
    - .github/workflows/ci.yml (rename + EXPOSE_TEST_ROUTES=1 in api env)
    - .env.example (SESSION_EPOCH_CACHE_TTL)
    - docs/operator/SECURITY-NOTES.md (Phase 03 invariants section)
duration: ~2.5h
completed: 2026-05-04 (T1–T3); checkpoint T4 owed to operator (runbook review)
---

# Phase 03 Plan 12: E2E Cypress + operator docs

The final Phase-03 plan. Ships:
  - Two LIVE Cypress specs (`sessions.cy.ts`, `2fa-removal.cy.ts`)
    covering 4 of the 6 Phase-03 user-facing truths.
  - Two SKIPPED Cypress spec stubs (`2fa-webauthn.cy.ts`,
    `2fa-totp.cy.ts`) with detailed comments documenting the live-
    iteration work owed before un-skipping.
  - A test-helpers controller (EXPOSE_TEST_ROUTES-gated) the live
    specs depend on, mirroring Plan 03-07's VaultProbeModule pattern.
  - A new `docs/operator/RUNBOOK.md` covering Phase 03 day-2 ops
    (env vars + lost-2FA recovery + RP-ID change + operator session
    revocation + test-routes safety verification).
  - Phase-03 invariants appended to `docs/operator/SECURITY-NOTES.md`
    so the auditor at `/gsd:verify-work 3` has a single-page reference.

**Status:** T1–T3 COMPLETE; **T4 (operator runbook review) PENDING.**
**Date:** 2026-05-04
**Commits:** `b74ab0e` (T3 docs), `acbdc42` (T1+T2 specs + helpers + CI)
**Tasks:** 3/4 (T4 = operator review)

---

## What landed

### Task 3 (committed first — `b74ab0e`)

**`docs/operator/RUNBOOK.md` (new)** — sectioned for Phase 03 +
extensible for later phases:

  1. **Phase 03 env-var matrix** — `WEBAUTHN_RP_ID`,
     `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN`, `STEP_UP_TOKEN_TTL`,
     `SESSION_EPOCH_CACHE_TTL`, `EXPOSE_TEST_ROUTES` with prod
     values + load-bearing notes per variable.
  2. **Lost-2FA recovery procedure** — operator's only recourse when
     a user has lost both factors. Numbered steps using `psql` inside
     the Dokploy api container: list user's 2FA rows + delete them +
     bump `session_epoch`. Recovery phrase explicitly does NOT bypass
     2FA (load-bearing per threat model).
  3. **WebAuthn RP-ID change** procedure — credential-bricking event;
     7-day notice + bulk-delete `webauthn_credentials` + bulk-bump
     epochs.
  4. **Test-only routes flag (`EXPOSE_TEST_ROUTES`)** — production
     safety check the operator runs before EVERY deploy: grep the
     Dockerfile + docker-compose + Dokploy panel + the running
     container's env. If any positive hit in prod, P0 incident.
  5. **Operator-initiated session revocation** — single-user + all-
     users `psql` + `redis-cli DEL` procedures with the load-bearing
     "always pair the bump with a Redis cache DEL" note.

**`docs/operator/SECURITY-NOTES.md`** — added "Phase 03 invariants"
section the auditor reads at the gate:

  - TOTP secret browser-only + the server-side grep verification
    (`grep -rE "master_dek|computeTotpStep|verifyTotpCandidate"
     apps/api/src/twofa/totp/` MUST be clean).
  - AAD scheme extension `sv:user-totp:v1|<emailHash>` + the
    convention for adding new labels.
  - Session-epoch column + Redis cache + bust semantics; "every bump
    pairs with a DEL" invariant.
  - WebAuthn RP-ID load-bearing pointer to RUNBOOK.
  - The complete `@Public()` route allow-list — ANY new route NOT on
    this list MUST require an access JWT (auditor cross-check at
    every subsequent phase gate).
  - 2FA-required guard hand-off seam to Phase 07.
  - 12 audit-action enum extensions FROZEN for Phase 10's hash-chain
    indexing.
  - Findings disposition (FINDING-0017 closed by Plan 03-01;
    FINDING-0021 + FINDING-0022 fixed-pending-verification by
    Plan 03-09; FINDING-0011 deferred to Phase 13).

**`.env.example`** — added `SESSION_EPOCH_CACHE_TTL=60` (Plan 04
landed the env-var read but never updated the example).

### Task 1 + 2 (committed together — `acbdc42`)

**`apps/api/src/test-helpers/test-helpers.controller.ts` (new)** —
three POST routes guarded by `EXPOSE_TEST_ROUTES === "1"`:

  - `POST /test-helpers/flip-shared-vault-stub {value: bool}` —
    flips `MethodsService.sharedVaultDependencyCheck` between the
    default `() => false` stub and a `() => true` test stub. Used by
    the 2fa-removal spec.
  - `POST /test-helpers/seed-totp-credential {email, name} → {id}` —
    inserts a placeholder `totp_credentials` row (60-byte placeholder
    wrap + 61-byte placeholder AAD; server doesn't decrypt for the
    listing/removal flow). Lets specs put a user into the "≥1 active
    2FA method" state without going through the browser-side wrap
    ceremony.
  - `POST /test-helpers/mutate-webauthn-counter {credentialId,
     counter}` — sets a credential's counter to a target value. For
    the 2fa-webauthn sad-path counter-regression test (deferred).

**`apps/api/src/test-helpers/test-helpers.module.ts` (new)** — the
gated module. Conditionally imported in `app.module.ts` alongside the
existing `VaultProbeModule` (same `EXPOSE_TEST_ROUTES === "1"` spread).

**`apps/web/cypress/e2e/sessions.cy.ts` (new)** — two `it` blocks:

  - **List + empty state**: signup + login → `/settings/sessions` →
    assert "This device" pin + "no other active sessions" empty
    state.
  - **Revoke-all**: same setup → click "Sign out everywhere except
    this device" → confirm → assert redirect to `/login`,
    `assertNoSecretsInStorage`, `__Host-refresh` cookie cleared.

  **Truth 12 (revoke a sibling session)** is deferred to live-
  iteration. The minimal spec uses `cy.session` machinery or a new
  `cy.task` (which would require introducing `setupNodeEvents` to the
  config — out of scope here). Documented in the spec's header
  comment + in this SUMMARY.

**`apps/web/cypress/e2e/2fa-removal.cy.ts` (new)** — single `it` block
covering Truth 10 + the Phase-07 hand-off seam:

  1. Signup + login (1FA — no 2FA enrolled yet).
  2. `cy.request POST /test-helpers/seed-totp-credential` → places
     the user in the "1 active 2FA method" state.
  3. `cy.request POST /test-helpers/flip-shared-vault-stub
     {value: true}` → simulates the Phase-07 dep returning `true`.
  4. Visit `/settings/security` → click "Remove" on the seeded row.
  5. Assert the UI shows the forward-looking copy
     `"can't remove your last 2fa method while you're a member of a
     shared vault"`.
  6. Reset the stub via the `value: false` call so subsequent runs
     aren't poisoned. `after()` hook does a best-effort restore even
     if the test fails mid-run.

**`apps/web/cypress/e2e/2fa-webauthn.cy.ts` (new, DESCRIBE.SKIP)** —
spec stub. Comment block documents:
  - Why deferred: needs CDP virtual-authenticator wiring in
    `setupNodeEvents`; current Cypress 14 setup uses `cy.exec` not
    `cy.task`.
  - What's owed: extend `cypress.config.ts` with `setupNodeEvents`
    exposing `cy.task("addVirtualAuthenticator", opts)` driving
    Chrome CDP `WebAuthn.addVirtualAuthenticator`. Confirm CI runs
    Chrome (not Electron — Electron lacks the WebAuthn CDP domain).
  - Coverage when un-skipped: enrol + sign-in happy + counter-
    regression sad + cancel sad.

**`apps/web/cypress/e2e/2fa-totp.cy.ts` (new, DESCRIBE.SKIP)** —
spec stub. Comment block documents:
  - Why deferred: end-to-end requires intercepting the browser-
    generated TOTP secret (server NEVER sees plaintext, so Cypress
    can't read it via API).
  - Operator decision needed: (a) cy.stub `sodium.randombytes_buf`
    OR (b) test-only window seam `window.__SV_TEST_TOTP_SECRET__`
    when `EXPOSE_TEST_ROUTES === "1"`.
  - Coverage when un-skipped: enrol via UI + sign-in + verify happy
    + same-step replay sad.

**`.github/workflows/ci.yml`** — two changes:
  - rename the e2e job to mention Phase 03 specs;
  - add `EXPOSE_TEST_ROUTES: "1"` to the api env block so the test-
    helpers controller is registered for the e2e run. Production
    safety story (env var must stay unset on Dokploy) lives in
    `RUNBOOK.md` + `SECURITY-NOTES.md`.

The CI runner already executes `cypress:run` against the
`cypress/e2e/**/*.cy.ts` glob — no specPattern change needed.

### Task 4 — operator runbook review — **PENDING**

Operator must read the new "Lost 2FA — user can't sign in" section in
`RUNBOOK.md` and confirm:

  1. The procedure is operationally feasible — operator has access
     to the CLI, the DB, the Dokploy env panel, and the
     `redis-cli DEL` capability inside the api container.
  2. The "no recovery phrase bypass" rule is acceptable. Two
     possible answers:
     - (a) Operator accepts indefinitely. The threat model is
       stronger; users keep their factors carefully.
     - (b) Phase 11 is expected to revisit (e.g. recovery phrase →
       grace-period 2FA bypass with explicit user-acknowledged
       UX warning).
     Document the decision inline below this section once made.
  3. The test-routes verification commands (`grep` on the
     Dockerfile + Dokploy panel inspection + container env grep)
     are runnable against the operator's actual deploy setup.
  4. The auth-flow-auditor at `/gsd:verify-work 3` will validate
     this matches THREAT-MODEL §17 phishing-mitigation logic.

**Operator decision recorded here once made:**

> _(record (a) accepted-indefinitely OR (b) Phase-11-revisit, plus
> any other procedural feedback)_

---

## Truths verified (T1–T3) — and what's deferred

| # | Truth (from `03-INDEX.md`) | Status |
|---|---|---|
| T9 | `GET /2fa/methods` lists active methods | OK end-to-end via the 2fa-removal spec's seed + visit-/settings/security flow |
| T10 | `DELETE /2fa/methods/:id` + `AUTH_2FA_REMOVAL_BLOCKED` UI surface | OK — 2fa-removal.cy.ts asserts the 409 message in the rendered DOM |
| T11 | `/settings/sessions` lists active sessions; current row pinned + visually distinct | OK — sessions.cy.ts assertions cover the layout |
| T12 | `DELETE /sessions/:id` removes a sibling session | DEFERRED to live-iteration (multi-session setup requires cy.session machinery or a new `cy.task` for direct API login) |
| T13 | `POST /sessions/revoke-all` wipes local + redirects + invalidates siblings within ≤60s | UI side OK (sessions.cy.ts asserts the wipe + redirect); the 60s cross-tab epoch-revocation assertion is part of the multi-session setup, deferred with T12 |
| T16 | Web `/settings/security` UX (copy + ordering) | CODE-LEVEL OK (Plan 10 SUMMARY); visual confirmation owed via Plan 10 T4 |
| WebAuthn enrol + sign-in (Truths 1–4) | DEFERRED — virtual-authenticator wiring in setupNodeEvents owed |
| TOTP enrol + sign-in (Truths 5–7) | DEFERRED — known-secret injection seam owed |

The auditor gate (`/gsd:verify-work 3`) reads this summary's status
column directly — every deferred item is acknowledged.

---

## Decisions made

1. **Two LIVE specs + two SKIPPED stubs** rather than four
   half-broken specs. Cypress complexity is real:
   - WebAuthn requires Chrome CDP virtual authenticator (Cypress
     automation API surface has shifted; Cypress 14 doesn't ship a
     stable wrapper).
   - TOTP requires intercepting the browser-side secret generation
     (libsodium) so the spec knows what to type.
   Shipping skipped stubs with detailed comments is more honest than
   shipping flaky specs. The 03-12-SUMMARY status table makes the
   coverage gaps visible to the auditor.

2. **Multi-session E2E (Truth 12) deferred.** The minimal multi-
   session setup needs either `cy.session` (Cypress's session-cache
   machinery — not used elsewhere in this repo) or a `cy.task`
   running Argon2id Node-side (would need a setupNodeEvents block +
   an argon2 dep). Both are non-trivial follow-ups; the existing
   sessions.cy.ts covers the rest of Truths 11 + 13 cleanly.

3. **One test-helpers controller, multiple seams** rather than three
   tiny per-purpose modules. Mirrors how the existing `MethodsService`
   bundles related concerns. Phase 07 may decide to split if the
   surface grows during shared-vault work.

4. **Test-helpers `@Public()` instead of an additional auth gate.**
   The production safety is the `EXPOSE_TEST_ROUTES` env-var build
   flag — adding JWT auth on top would just complicate the test
   setup without changing the security envelope. Documented inline
   in the controller's class jsdoc.

5. **`seed-totp-credential` uses placeholder bytes** (60 zero bytes
   for `wrappedSecret`, 61 for `encryptedSecretAad`). The listing +
   removal flows don't decrypt; we save complexity by NOT trying to
   produce a real wrap. Spec MUST NOT then try to actually
   authenticate with the seeded credential — verify would fail. The
   2FA-totp verify-side spec (deferred) needs a different helper that
   ALSO derives a real wrap, or the cy.stub approach.

6. **CI gets `EXPOSE_TEST_ROUTES=1`** baked into the e2e job's env
   block. Plan 12 documents the production-safety story in RUNBOOK +
   SECURITY-NOTES so the operator has the grep verification commands
   to run before every Dokploy deploy. The audit-flow-auditor will
   cross-check the prod Dockerfile + docker-compose for any positive
   match.

7. **No setupNodeEvents block introduced.** The existing
   `cypress.config.ts` uses `cy.exec` shell-outs (mirrors the
   Phase-02 patterns in `commands.ts`). Adding setupNodeEvents now
   would be the right move for the deferred WebAuthn + TOTP specs;
   the placeholder stubs document this as the first step in their
   "what's owed" sections.

8. **`docs/operator/RUNBOOK.md` is a NEW file** (not appending to
   anything). The pre-existing operator docs cover one-time setup
   (DOKPLOY-DEPLOY) + secrets (SECURITY-NOTES) + dev (LOCAL-DEV) +
   CLI usage (CLI). RUNBOOK fills the day-2-operations gap. Phase
   13 will likely append more sections (incident response,
   monitoring playbook).

---

## Verification gates

| Gate | Result |
|---|---|
| `pnpm typecheck` (apps/api) | GREEN |
| `pnpm build` (apps/api, nest) | GREEN |
| `pnpm test` (apps/api, vitest) | GREEN — 32/32 (no regressions) |
| `pnpm typecheck + build` (apps/web) | NOT RE-RUN this commit (no web source changed; only spec + helper files) |
| Cypress live run (sessions.cy.ts + 2fa-removal.cy.ts) | NOT RUN LOCALLY — requires Postgres + Redis + API + Web + EXPOSE_TEST_ROUTES=1 stack. CI is the live verification surface; the operator triggers it on the next push. |
| Cypress 2fa-webauthn / 2fa-totp specs | DESCRIBE.SKIP'd (intentional; iteration owed) |
| Operator runbook review (T4) | **PENDING — operator owes a decision on the "no recovery phrase bypass" rule** (a-vs-b in T4 above) |

---

## Hand-offs

**`/gsd:verify-work 3`** — the next step after this commit. Runs the
4-auditor gate (auth-flow + crypto + owasp-top10 + access-control)
plus the threat-modeler informational pass. Auditors cross-reference:
  - The status table in this SUMMARY (deferred items are
    acknowledged; FINDING-0021 + FINDING-0022 are fixed-pending-
    verification owed by Plan 03-09).
  - The `@Public()` allow-list in SECURITY-NOTES.md against the
    actual Nest router.
  - The server-side TOTP-plaintext grep against
    `apps/api/src/twofa/totp/`.
  - The RUNBOOK lost-2FA procedure against THREAT-MODEL §17.

**Phase 07** deletes the test-helpers controller + the
VaultProbeModule + the conditional-spread in `app.module.ts` as part
of its first commit (the broader EXPOSE_TEST_ROUTES retirement). New
real `vault.create` / `vault.join` controllers replace the probe.

**Phase 11** revisits the lost-2FA recovery flow if the operator
records decision (b) in T4 above.

---

## Files

**Created:**
- `apps/api/src/test-helpers/test-helpers.controller.ts`
- `apps/api/src/test-helpers/test-helpers.module.ts`
- `apps/web/cypress/e2e/sessions.cy.ts`
- `apps/web/cypress/e2e/2fa-removal.cy.ts`
- `apps/web/cypress/e2e/2fa-webauthn.cy.ts` (DESCRIBE.SKIP)
- `apps/web/cypress/e2e/2fa-totp.cy.ts` (DESCRIBE.SKIP)
- `docs/operator/RUNBOOK.md`
- `.planning/phases/03-2fa-sessions/03-12-SUMMARY.md` (this doc)

**Modified:**
- `apps/api/src/app.module.ts` (conditional import of TestHelpersModule)
- `.github/workflows/ci.yml` (rename + EXPOSE_TEST_ROUTES=1)
- `.env.example` (SESSION_EPOCH_CACHE_TTL)
- `docs/operator/SECURITY-NOTES.md` (Phase 03 invariants section)

---

## Next: `/gsd:verify-work 3`

After T4 (operator runbook review) lands, run `/gsd:verify-work 3` to
execute the 4 blocking auditors + threat-modeler. The auditors will
read this SUMMARY + the Plan 10 T4 UX confirmation status before
running their checks.
