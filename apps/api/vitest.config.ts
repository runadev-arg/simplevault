import { defineConfig } from "vitest/config";

/**
 * Phase 03 Plan 04 — first vitest target inside `apps/api`.
 *
 * Unit-level tests against in-process Nest providers (no docker, no real
 * postgres/redis). End-to-end coverage with real services lives in Plan 12
 * (CI cypress + service containers).
 */
export default defineConfig({
  test: {
    include: ["test/**/*.spec.ts"],
    environment: "node",
    testTimeout: 15_000,
    hookTimeout: 15_000,
    pool: "forks",
  },
});
