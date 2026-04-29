import { createDbClient, type DbClient } from "@simplevault/db";
import type { Pool } from "pg";

/**
 * Open a Drizzle client using `DATABASE_URL`. Fail fast if unset.
 * Returns the client + pool so the caller can `pool.end()` cleanly.
 */
export function openDb(): { db: DbClient; pool: Pool } {
  const url = process.env["DATABASE_URL"];
  if (!url || url.length === 0) {
    process.stderr.write(
      "ERROR: DATABASE_URL is not set. Required to issue invite codes.\n",
    );
    process.exit(2);
  }
  // Suppress Drizzle's dev-mode query logger (writes to stdout otherwise);
  // the CLI must NOT log query params — they include the HMAC code_hash.
  if (process.env["NODE_ENV"] === undefined || process.env["NODE_ENV"] === "development") {
    process.env["NODE_ENV"] = "production";
  }
  return createDbClient({ connectionString: url });
}
