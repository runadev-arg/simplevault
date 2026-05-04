/// <reference types="cypress" />
import { HAPPY_PASSWORD } from "../fixtures/seed";

/**
 * Phase 03 Plan 12 — 2FA-removal Cypress spec.
 *
 * Covers Truth 10 (`AUTH_2FA_REMOVAL_BLOCKED` 409 on removal-blocked) +
 * the Phase-07 hand-off seam — the spec uses the test-helpers controller
 * to flip the `MethodsService.sharedVaultDependencyCheck` stub to `true`
 * and asserts the UI surfaces the forward-looking shared-vault copy.
 *
 * **Live-stack expectations** (additional to `auth-happy.cy.ts` contract):
 *   - apps/api MUST be started with `EXPOSE_TEST_ROUTES=1` in the env so
 *     the test-helpers controller is registered. Production MUST leave
 *     it unset (see RUNBOOK).
 */

const EMAIL = "removal@test.local";
const API = Cypress.env("apiUrl") as string;

describe("2FA — removal-guard 409 surfaces in /settings/security", () => {
  beforeEach(() => {
    cy.resetDb();
  });

  after(() => {
    // Best-effort restore the stub even if the test failed mid-run.
    cy.request({
      method: "POST",
      url: `${API}/test-helpers/flip-shared-vault-stub`,
      body: { value: false },
      failOnNonZeroExit: false,
    });
  });

  it("removing the last method while shared-vault dep is true → AUTH_2FA_REMOVAL_BLOCKED", () => {
    // ---- Setup: signup + login (1FA path; no 2FA enrolled yet) ----
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

    // ---- Seed a TOTP credential server-side (placeholder wrap) ----
    cy.request({
      method: "POST",
      url: `${API}/test-helpers/seed-totp-credential`,
      body: { email: EMAIL, name: "Test Authenticator" },
    }).its("body.id").should("match", /^[0-9a-f-]{36}$/i);

    // ---- Flip the shared-vault stub to true so the next removal 409s ----
    cy.request({
      method: "POST",
      url: `${API}/test-helpers/flip-shared-vault-stub`,
      body: { value: true },
    });

    // ---- Visit /settings/security and try to remove the seeded method ----
    cy.visit("/settings/security");
    cy.contains("Test Authenticator", { timeout: 15_000 });
    cy.contains("li", "Test Authenticator").within(() => {
      cy.contains("button", /remove/i).click();
    });
    cy.contains(
      /can't remove your last 2fa method while you're a member of a shared vault/i,
      { timeout: 15_000 },
    ).should("exist");

    // The row MUST still be present after the failed remove.
    cy.contains("Test Authenticator").should("exist");

    // ---- Reset the stub so subsequent tests / reruns aren't poisoned ----
    cy.request({
      method: "POST",
      url: `${API}/test-helpers/flip-shared-vault-stub`,
      body: { value: false },
    });
  });
});

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
