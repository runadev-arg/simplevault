import { defineConfig } from "cypress";

/**
 * Cypress E2E config for SimpleVault.
 *
 * Targets a running stack: web on http://localhost:3000, api on
 * http://localhost:3001. The api MUST be reachable as a same-origin path
 * `/api/*` in production (per 02-11 SUMMARY: __Host- cookie requirement),
 * but in tests we hit `apiUrl` directly via `cy.request` for sad-path
 * shape comparisons; the wizard's JS uses `NEXT_PUBLIC_API_URL` to talk
 * to the api.
 *
 * E2E expectations from the operator running `pnpm e2e`:
 *  - `docker compose up -d postgres redis` is up.
 *  - `pnpm db:migrate` has run.
 *  - `apps/api` is up on :3001 with TEST env (low-cost Argon2 params).
 *  - `apps/web` is up on :3000 with NEXT_PUBLIC_API_URL=http://localhost:3001.
 *  - `pnpm cli build` has produced apps/cli/dist/main.js.
 *  - LOGIN_IP_RATE_LIMIT and SIGNUP_IP_RATE_LIMIT are set high enough
 *    NOT to trip during the happy spec but are still configured so the
 *    rate-limit smoke spec can opt-in (see auth-sad.cy.ts).
 *
 * The CI runner reproduces this contract end-to-end (see
 * .github/workflows/ci.yml `e2e` job).
 */
export default defineConfig({
  e2e: {
    baseUrl: "http://localhost:3000",
    specPattern: "cypress/e2e/**/*.cy.ts",
    supportFile: "cypress/support/e2e.ts",
    fixturesFolder: "cypress/fixtures",
    screenshotsFolder: "cypress/screenshots",
    videosFolder: "cypress/videos",
    video: false, // CI uploads only on failure; videos balloon artifact size.
    viewportWidth: 1280,
    viewportHeight: 800,
    // The signup wizard derives Argon2id in browser — slow even on test
    // params. 60s default is too tight for a cold WASM init + derivation.
    defaultCommandTimeout: 30_000,
    requestTimeout: 30_000,
    pageLoadTimeout: 60_000,
    // Retry once on flake — sodium WASM cold-start can be jittery.
    retries: { runMode: 1, openMode: 0 },
    env: {
      apiUrl: "http://localhost:3001",
      // The CLI binary built by `pnpm cli:build`.
      cliBin: "node ../cli/dist/main.js",
    },
  },
});
