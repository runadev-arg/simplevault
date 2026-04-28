import type { Config } from "drizzle-kit";

export default {
  // Drizzle Kit uses CJS-style require and can't resolve our NodeNext `.js`
  // extension imports. Point it directly at the per-table schema modules
  // (skipping the barrel `index.ts`) so it never has to follow `./users.js`.
  schema: ["./src/schema/users.ts"],
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL ?? "postgres://localhost:5432/simplevault",
  },
  strict: true,
  verbose: true,
} satisfies Config;
