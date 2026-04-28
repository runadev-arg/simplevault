import { Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { Redis } from "ioredis";

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private _redis!: Redis;

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const url = this.config.get<string>("REDIS_URL") ?? process.env.REDIS_URL ?? "redis://localhost:6379";
    this._redis = new Redis(url, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      retryStrategy: (times) => Math.min(times * 200, 2000),
    });
    // Surface connection errors as logs without crashing.
    this._redis.on("error", (err) => {
      this.logger.warn({ err: err.message }, "redis connection error");
    });
    this.logger.log("Redis client initialized");
  }

  async onModuleDestroy(): Promise<void> {
    try {
      this._redis.disconnect();
      this.logger.log("Redis client disconnected");
    } catch (err) {
      this.logger.error({ err }, "error disconnecting Redis client");
    }
    return Promise.resolve();
  }

  get client(): Redis {
    return this._redis;
  }

  async ping(): Promise<"ok" | "down"> {
    try {
      const res: string = await this._redis.ping();
      return res === "PONG" ? "ok" : "down";
    } catch {
      return "down";
    }
  }
}
