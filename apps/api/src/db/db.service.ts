import { Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createDbClient, type DbClient } from "@simplevault/db";
import type { Pool } from "pg";

@Injectable()
export class DbService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DbService.name);
  private _db!: DbClient;
  private _pool!: Pool;

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const connectionString = this.config.get<string>("DATABASE_URL") ?? process.env.DATABASE_URL;
    if (!connectionString) {
      this.logger.warn("DATABASE_URL not set; DbService initialized in degraded mode (pings will fail)");
      // Still create a pool with a placeholder so pings simply fail rather than crashing the app.
      const { db, pool } = createDbClient({ connectionString: "postgres://invalid:5432/none" });
      this._db = db;
      this._pool = pool;
      return;
    }
    const { db, pool } = createDbClient({ connectionString });
    this._db = db;
    this._pool = pool;
    this.logger.log("Drizzle pool initialized");
  }

  async onModuleDestroy(): Promise<void> {
    try {
      await this._pool.end();
      this.logger.log("Drizzle pool closed");
    } catch (err) {
      this.logger.error({ err }, "error closing Drizzle pool");
    }
  }

  get db(): DbClient {
    return this._db;
  }

  async ping(): Promise<"ok" | "down"> {
    try {
      const res = await this._pool.query<{ ok: number }>("SELECT 1 as ok");
      return res.rows[0]?.ok === 1 ? "ok" : "down";
    } catch {
      return "down";
    }
  }
}
