import nextConfig from "@simplevault/eslint-config/next";

// Cypress E2E specs are tsconfig-isolated under cypress/tsconfig.json
// (project-service in the shared strict config can't see them). Vitest
// unit specs (`src/**/*.test.ts`, e.g. AAD label byte-assertions added
// in Plan 04-01) are likewise outside the typed-lint project — they run
// under their own vitest config and don't need Next-build-time linting.
export default [...nextConfig, { ignores: ["cypress/**", "src/**/*.test.ts", "vitest.config.ts"] }];
