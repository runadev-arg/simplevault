/// <reference types="cypress" />
import { HAPPY_PASSWORD } from "../fixtures/seed";

/**
 * Phase 02 happy-path E2E.
 *
 * Walks the full lifecycle:
 *   1. CLI issues an invite for happy@test.local.
 *   2. Browser at /signup redeems the code.
 *   3. Wizard advances through all 7 steps:
 *      master pw -> secret_key reveal+confirm -> mnemonic reveal+confirm
 *      -> Argon2id derivation -> POST /auth/signup -> redirect to /login.
 *   4. Login again with same credentials (email + master pw + secret_key).
 *   5. /me shows the email.
 *   6. Click logout, verify redirect to /login.
 *   7. Login one more time to assert the session-row transitions are clean.
 *
 * Storage hygiene asserted at every checkpoint.
 */

const EMAIL = "happy@test.local";

describe("Auth happy path", () => {
  beforeEach(() => {
    cy.resetDb();
  });

  it("invite -> signup -> login -> /me -> logout -> login again", () => {
    cy.seedInvite(EMAIL).then((code) => {
      // ---- Step 1: signup wizard ----
      cy.visit("/signup");

      // 1a. invite code
      cy.get("input#invite").type(code);
      cy.contains("button", "Continue").click();

      // 1b. master password
      cy.get("input#pw", { timeout: 15_000 }).type(HAPPY_PASSWORD);
      cy.get("input#confirm").type(HAPPY_PASSWORD);
      cy.contains("button", "Continue").click();

      // 1c. secret-key reveal — capture the displayed value, re-paste,
      // tick the ack, advance.
      cy.get(".tracking-widest", { timeout: 30_000 })
        .invoke("text")
        .then((text) => {
          const sk = text.trim();
          cy.wrap(sk).as("secretKey");
          cy.get('input[type="checkbox"]').check();
          cy.get("input#confirm-sk").type(sk);
          cy.contains("button", "Continue").click();
        });

      // 1d. mnemonic reveal — capture the 24 words, ack, advance.
      cy.get("ol li", { timeout: 30_000 })
        .should("have.length", 24)
        .then(($lis) => {
          const words: string[] = [];
          $lis.each((_, el) => {
            // The DOM is "<span>1.</span>word"; words[i] = lastChild text.
            const last = el.lastChild;
            if (last && last.nodeType === Node.TEXT_NODE) {
              words.push((last.textContent ?? "").trim());
            } else {
              // Fallback — strip the "N." prefix.
              const txt = (el.textContent ?? "").replace(/^\d+\.\s*/, "").trim();
              words.push(txt);
            }
          });
          cy.wrap(words).as("mnemonic");
          cy.get('input[type="checkbox"]').check();
          cy.contains("button", "Continue").click();
        });

      // 1e. mnemonic confirm — read the challenge indices from the DOM
      // and type the right words. The confirm step renders 4 inputs
      // with id `w<idx>` and a label "Word #<idx+1>".
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

      // 1f. Submitting step does Argon2id derivation client-side then
      // POST /auth/signup. On success the wizard redirects to
      // /login?signed_up=1.
      cy.url({ timeout: 60_000 }).should("include", "/login");
      cy.assertNoSecretsInStorage();

      // ---- Step 2: login ----
      cy.get<string>("@secretKey").then((sk) => {
        cy.get("input#email").type(EMAIL);
        cy.get("input#password").type(HAPPY_PASSWORD);
        cy.get("input#secret-key").type(sk);
        cy.contains("button", "Sign in").click();
      });

      // ---- Step 3: /me ----
      cy.url({ timeout: 60_000 }).should("include", "/me");
      cy.contains(EMAIL, { timeout: 15_000 });
      cy.assertNoSecretsInStorage();

      // ---- Step 4: logout ----
      cy.contains("button", "Logout").click();
      cy.url({ timeout: 15_000 }).should("include", "/login");
      cy.assertNoSecretsInStorage();
      cy.getCookie("__Host-refresh").should("be.null");

      // ---- Step 5: login again — proves credentials persist + a fresh
      // session row is created cleanly.
      cy.get<string>("@secretKey").then((sk) => {
        cy.get("input#email", { timeout: 15_000 }).type(EMAIL);
        cy.get("input#password").type(HAPPY_PASSWORD);
        cy.get("input#secret-key").type(sk);
        cy.contains("button", "Sign in").click();
      });
      cy.url({ timeout: 60_000 }).should("include", "/me");
      cy.contains(EMAIL);
      cy.assertNoSecretsInStorage();
    });
  });
});
