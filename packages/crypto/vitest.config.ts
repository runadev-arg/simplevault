import { defineConfig } from "vitest/config";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

// libsodium-wrappers-sumo's published ESM build references a sibling
// libsodium-sumo.mjs that isn't shipped, breaking ESM resolution under
// vitest. Force the CJS bundle (which IS shipped and pulls in the right
// libsodium-sumo CJS file). The browser/node barrels still consume it as
// a default import; tsconfig esModuleInterop handles that fine.
const sodiumCjs = require.resolve("libsodium-wrappers-sumo");

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    testTimeout: 30_000,
    hookTimeout: 30_000,
    pool: "forks",
  },
  resolve: {
    alias: {
      "libsodium-wrappers-sumo": sodiumCjs,
    },
  },
});
