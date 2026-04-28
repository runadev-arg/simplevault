import { migrate } from "drizzle-orm/node-postgres/migrator";

import { createDbClient } from "./client.js";

const url = process.env.DATABASE_URL;
if (!url) {
  console.error("[migrate] DATABASE_URL is required");
  process.exit(1);
}

const { db, pool } = createDbClient({ connectionString: url });

try {
  await migrate(db, { migrationsFolder: "./drizzle" });
  console.log("[migrate] Migrations applied");
} catch (err) {
  console.error("[migrate] Migration failed:", err);
  process.exit(1);
} finally {
  await pool.end();
}
