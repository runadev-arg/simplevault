/// <reference types="cypress" />
import { HAPPY_PASSWORD } from "../fixtures/seed";

/**
 * Phase 03 Plan 12 — `/settings/sessions` E2E.
 *
 * Covers Truths 11 + 13 from `.planning/phases/03-2fa-sessions/03-INDEX.md`:
 *   - List active sessions (current row pinned + visually distinct).
 *   - "Sign out everywhere except this device" wipes local state +
 *     redirects to /login.
 *
 * **Deferred to live-iteration:** Truth 12 (revoke a sibling session +
 * verify it actually 401s) — requires a multi-session setup that needs
 * either `cy.session` machinery or a setupNodeEvents-defined `cy.task`
 * for direct API login. Documented in 03-12-SUMMARY as owed.
 *
 * **Live-stack expectations** (same contract as `auth-happy.cy.ts`).
 */

const EMAIL = "sessions@test.local";

describe("Sessions management — /settings/sessions", () => {
  beforeEach(() => {
    cy.resetDb();
  });

  it("shows the current session pinned + 'no other sessions' empty state", () => {
    cy.seedInvite(EMAIL).then((code) => {
      cy.visit("/signup");
      walkSignupWizard(code);
      cy.url({ timeout: 60_000 }).should("include", "/login");
    });

    // Login (session #1 = "this device").
    cy.get<string>("@secretKey").then((sk) => {
      cy.get("input#email").type(EMAIL);
      cy.get("input#password").type(HAPPY_PASSWORD);
      cy.get("input#secret-key").type(sk);
      cy.contains("button", "Sign in").click();
    });
    cy.url({ timeout: 60_000 }).should("include", "/me");

    // Visit /settings/sessions and assert the layout.
    cy.visit("/settings/sessions");
    cy.contains("h1", "Active sessions", { timeout: 15_000 });
    cy.contains("This device").should("exist");
    // Only the current session exists → empty state for others.
    cy.contains("You have no other active sessions.").should("exist");
  });

  it("revoke-all wipes local state + redirects to /login", () => {
    cy.seedInvite(EMAIL).then((code) => {
      cy.visit("/signup");
      walkSignupWizard(code);
      cy.url({ timeout: 60_000 }).should("include", "/login");
    });

    cy.get<string>("@secretKey").then((sk) => {
      cy.get("input#email").type(EMAIL);
      cy.get("input#password").type(HAPPY_PASSWORD);
      cy.get("input#secret-key").type(sk);
      cy.contains("button", "Sign in").click();
    });
    cy.url({ timeout: 60_000 }).should("include", "/me");

    cy.visit("/settings/sessions");
    cy.contains("button", /sign out everywhere except this device/i, {
      timeout: 15_000,
    }).click();
    cy.contains("button", /confirm — sign out everywhere/i).click();

    cy.url({ timeout: 15_000 }).should("include", "/login");
    cy.assertNoSecretsInStorage();
    cy.getCookie("__Host-refresh").should("be.null");
  });
});

/**
 * Walks the 7-step signup wizard. Assumes you're at /signup with `code`
 * already known. Stashes the secret-key + mnemonic via cy.wrap aliases
 * (`@secretKey`, `@mnemonic`) for the caller to consume after the wizard
 * exits to /login.
 *
 * Mirrors the wizard helper in `auth-happy.cy.ts`. Pulled out here as a
 * local helper — extracting to support/commands.ts is a Phase 13
 * cleanup if more specs reuse it.
 */
function walkSignupWizard(code: string): void {
  cy.get("input#invite").type(code);
  cy.contains("button", "Continue").click();

  cy.get("input#pw", { timeout: 15_000 }).type(HAPPY_PASSWORD);
  cy.get("input#confirm").type(HAPPY_PASSWORD);
  cy.contains("button", "Continue").click();

  cy.get(".tracking-widest", { timeout: 30_000 })
    .invoke("text")
    .then((text) => {
      const sk = text.trim();
      cy.wrap(sk).as("secretKey");
      cy.get('input[type="checkbox"]').check();
      cy.get("input#confirm-sk").type(sk);
      cy.contains("button", "Continue").click();
    });

  cy.get("ol li", { timeout: 30_000 })
    .should("have.length", 24)
    .then(($lis) => {
      const words: string[] = [];
      $lis.each((_, el) => {
        const last = el.lastChild;
        if (last && last.nodeType === Node.TEXT_NODE) {
          words.push((last.textContent ?? "").trim());
        } else {
          const txt = (el.textContent ?? "").replace(/^\d+\.\s*/, "").trim();
          words.push(txt);
        }
      });
      cy.wrap(words).as("mnemonic");
      cy.get('input[type="checkbox"]').check();
      cy.contains("button", "Continue").click();
    });

  cy.get<string[]>("@mnemonic").then((words) => {
    cy.get('input[id^="w"]', { timeout: 15_000 })
      .should("have.length", 4)
      .each(($input) => {
        const id = ($input.attr("id") ?? "").replace(/^w/, "");
        const idx = Number.parseInt(id, 10);
        const word = words[idx];
        if (!word) throw new Error(`No word at index ${id}`);
        cy.wrap($input).type(word);
      });
    cy.contains("button", "Verify and continue").click();
  });
}
