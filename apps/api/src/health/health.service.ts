import { Injectable } from "@nestjs/common";
import type { HealthResponse } from "@simplevault/shared/zod";

import { DbService } from "../db/db.service.js";
import { RedisService } from "../redis/redis.service.js";

@Injectable()
export class HealthService {
  constructor(
    private readonly db: DbService,
    private readonly redis: RedisService,
  ) {}

  async check(): Promise<HealthResponse> {
    const [db, redis] = await Promise.all([this.db.ping(), this.redis.ping()]);
    const status: HealthResponse["status"] = db === "ok" && redis === "ok" ? "ok" : "degraded";
    return { status, db, redis, timestamp: new Date().toISOString() };
  }
}
