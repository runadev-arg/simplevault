import type { Config } from "drizzle-kit";

export default {
  // Drizzle Kit uses CJS-style require and can't resolve our NodeNext `.js`
  // extension imports. Point it directly at the per-table schema modules
  // (skipping the barrel `index.ts`) so it never has to follow `./users.js`.
  schema: [
    "./src/schema/users.ts",
    "./src/schema/user_sessions.ts",
    "./src/schema/invite_codes.ts",
    "./src/schema/webauthn_credentials.ts",
    "./src/schema/webauthn_challenges.ts",
    "./src/schema/totp_credentials.ts",
    "./src/schema/vaults.ts",
    "./src/schema/credentials.ts",
    "./src/schema/pages.ts",
    "./src/schema/page_versions.ts",
  ],
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL ?? "postgres://localhost:5432/simplevault",
  },
  strict: true,
  verbose: true,
} satisfies Config;
