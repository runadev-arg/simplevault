// Cypress E2E support file — loaded before every spec.
// Wires up custom commands.
import "./commands";

// Fail fast on uncaught application errors. The signup wizard does
// libsodium WASM bootstrap which can throw in jsdom-style environments
// — Cypress runs a real Chromium so this should never trigger.
Cypress.on("uncaught:exception", (err) => {
  // Returning false here prevents Cypress from failing the test.
  // We DO want it to fail so we know about runtime regressions, EXCEPT
  // for the well-known libsodium "Ready event" double-fire which is
  // benign.
  if (/sodium.*ready/i.test(err.message)) return false;
  return true;
});
