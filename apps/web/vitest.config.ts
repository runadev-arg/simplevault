import { defineConfig } from "vitest/config";

// Phase 04 — minimal vitest setup so we can byte-assert FROZEN AAD label
// literals (apps/web/src/lib/crypto/aad-labels.test.ts). The test runner
// is intentionally scoped to pure-TS unit specs; component / DOM testing
// is out of scope until a future phase adds it explicitly.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
  },
});
