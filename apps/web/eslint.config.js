import nextConfig from "@simplevault/eslint-config/next";

// Cypress E2E specs are tsconfig-isolated under cypress/tsconfig.json
// (project-service in the shared strict config can't see them).
export default [...nextConfig, { ignores: ["cypress/**"] }];
