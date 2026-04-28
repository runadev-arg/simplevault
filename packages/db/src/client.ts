import { drizzle } from "drizzle-orm/node-postgres";
import { Pool, type PoolConfig } from "pg";

import * as schema from "./schema/index.js";

export type DbClient = ReturnType<typeof drizzle<typeof schema>>;

export interface CreateDbClientOptions {
  connectionString: string;
  poolConfig?: Omit<PoolConfig, "connectionString">;
}

export function createDbClient({
  connectionString,
  poolConfig,
}: CreateDbClientOptions): { db: DbClient; pool: Pool } {
  const pool = new Pool({
    connectionString,
    max: 10,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    ...poolConfig,
  });
  const db = drizzle(pool, { schema, logger: process.env.NODE_ENV !== "production" });
  return { db, pool };
}
