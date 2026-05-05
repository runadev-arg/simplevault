import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Phase 04 — vitest setup. Pure-TS unit specs run in node; component specs
// (*.test.tsx) run in jsdom (per-file via environmentMatchGlobs) so we don't
// pay the jsdom startup cost on pure-TS specs. The react plugin enables the
// automatic JSX runtime for .tsx specs.
export default defineConfig({
  plugins: [react()],
  test: {
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    environment: "node",
    environmentMatchGlobs: [["src/**/*.test.tsx", "jsdom"]],
  },
});
