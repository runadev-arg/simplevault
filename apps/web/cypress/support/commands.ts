/// <reference types="cypress" />

/**
 * Custom Cypress commands for SimpleVault E2E.
 *
 * cy.seedInvite(email)
 *   Shells out to `pnpm cli invite create --email <email>` and yields the
 *   stdout-printed code (first line). Requires `pnpm cli build` to have
 *   produced apps/cli/dist/main.js and DATABASE_URL + SERVER_INVITE_SECRET
 *   in the spawned env.
 *
 * cy.resetDb()
 *   Truncates the auth-related tables so each spec is hermetic. Uses a
 *   small `psql` invocation. CI sets DATABASE_URL; the spec inherits it.
 *
 * cy.assertNoSecretsInStorage()
 *   Asserts localStorage / sessionStorage / cookie store are empty of the
 *   well-known secret-shaped keys. Access JWT lives in JS memory only;
 *   refresh token is HttpOnly so document.cookie can NOT see it.
 */

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Cypress {
    interface Chainable<Subject = unknown> {
      seedInvite(email: string): Chainable<string>;
      resetDb(): Chainable<void>;
      assertNoSecretsInStorage(): Chainable<void>;
    }
  }
}

const FORBIDDEN_KEY_PATTERNS = [
  /token/i,
  /secret/i,
  /password/i,
  /dek/i,
  /kek/i,
  /mnemonic/i,
  /recovery/i,
  /argon/i,
];

Cypress.Commands.add("seedInvite", (email: string) => {
  const cliBin = Cypress.env("cliBin") as string;
  // `cy.exec` runs from the spec's cwd which is `apps/web`. The
  // CLI binary path in cypress.config.ts is relative to that.
  return cy
    .exec(`${cliBin} invite create --email ${email}`, {
      env: {
        // Pass through the CI/dev env. `cy.exec` inherits process env by
        // default but we explicitly assert what's needed for the CLI:
        DATABASE_URL: Cypress.env("DATABASE_URL") ?? process.env.DATABASE_URL ?? "",
        SERVER_INVITE_SECRET:
          Cypress.env("SERVER_INVITE_SECRET") ?? process.env.SERVER_INVITE_SECRET ?? "",
      },
      failOnNonZeroExit: true,
      timeout: 20_000,
    })
    .then((res) => {
      // Stdout line 1 is the code; line 3 the OOB hint. Capture line 1.
      const code = res.stdout.split("\n").map((l) => l.trim()).find((l) => /^[0-9A-HJKMNP-TV-Z-]{8,64}$/i.test(l));
      if (!code) {
        throw new Error(`seedInvite: could not parse code from CLI stdout:\n${res.stdout}`);
      }
      return cy.wrap(code);
    });
});

Cypress.Commands.add("resetDb", () => {
  // Truncate auth-related tables. Uses psql from the env.
  // We use TRUNCATE ... CASCADE so user_sessions + invite_codes drain too.
  const sql = "TRUNCATE TABLE users, user_sessions, invite_codes RESTART IDENTITY CASCADE;";
  cy.exec(`psql "$DATABASE_URL" -c "${sql}"`, {
    failOnNonZeroExit: true,
    timeout: 15_000,
  });
});

Cypress.Commands.add("assertNoSecretsInStorage", () => {
  cy.window().then((win) => {
    for (let i = 0; i < win.localStorage.length; i++) {
      const k = win.localStorage.key(i);
      const v = k ? win.localStorage.getItem(k) : null;
      for (const re of FORBIDDEN_KEY_PATTERNS) {
        expect(k, `localStorage key "${k}" must not look like a secret`).to.not.match(re);
        if (v) expect(v, `localStorage value at "${k}" must not look like a secret`).to.not.match(re);
      }
    }
    for (let i = 0; i < win.sessionStorage.length; i++) {
      const k = win.sessionStorage.key(i);
      for (const re of FORBIDDEN_KEY_PATTERNS) {
        expect(k, `sessionStorage key "${k}" must not look like a secret`).to.not.match(re);
      }
    }
    // document.cookie cannot read HttpOnly cookies, so the refresh token
    // is invisible here — which is exactly what we want to assert.
    const cookies = win.document.cookie;
    expect(cookies, "document.cookie must not expose the refresh cookie").to.not.match(/refresh/i);
  });
});

export {};
