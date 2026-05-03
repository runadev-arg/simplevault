import { Injectable, Logger, type OnModuleDestroy, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { schema } from "@simplevault/db";
import { eq } from "drizzle-orm";
import { Redis } from "ioredis";

import { DbService } from "../../db/db.service.js";

const KEY_PREFIX = "session-epoch:";
const DEFAULT_TTL_SEC = 60;

/**
 * Per-user session-epoch cache (Phase 03 / Plan 04).
 *
 * Truth 14 of `03-INDEX.md`: every authenticated request reads
 * `users.session_epoch` to compare against the JWT's `epoch` claim. A naive
 * implementation would be a `users` row hit per request; this wrapper adds
 * a Redis-backed cache (TTL `SESSION_EPOCH_CACHE_TTL`, default 60s) plus a
 * per-userId in-flight Map so concurrent cold-cache callers coalesce to a
 * single DB read.
 *
 * Cache busting strategy: **DEL after the DB UPDATE** (NOT SET-with-new-value).
 * Rationale (per 03-04-PLAN Key Link 1): a `SET` race is real:
 *
 *   T1: cache.get(u) reads DB, sees epoch=N
 *   T2: bumpEpoch updates DB to N+1
 *   T2: bumpEpoch SETs cache to N+1
 *   T1: cache.set(u, N)  ← stale value wins
 *
 * With DEL, T1's cache.set is harmless: the next read just queries the DB
 * again and observes the post-UPDATE value. Worst-case: a 5ms window where
 * the cache holds the stale `N`, bounded by Redis-DEL latency.
 *
 * On Redis outage every method falls back to a direct DB read — auth must
 * never fail-open, but a cache miss is only a perf regression, not a
 * correctness one.
 */
@Injectable()
export class SessionEpochCache implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(SessionEpochCache.name);
  private redis!: Redis;
  private cacheTtlSec = DEFAULT_TTL_SEC;
  /** Per-userId in-flight map → coalesces concurrent cold reads into one DB query. */
  private readonly inflight = new Map<string, Promise<number>>();
  /**
   * Per-userId monotonic counter, incremented on every `bust(userId)`. The
   * cold-path handler captures the counter BEFORE its DB read and only
   * writes the value back to Redis if the counter is unchanged afterwards
   * — i.e. no bust raced through during our DB hop. This closes the
   * "stale-set" race the plan's Key Link 1 calls out:
   *
   *   T1: get → captures genBefore=0, snapshots DB at epoch=N
   *   T2: bumpEpoch updates DB→N+1, bust → genCounter[u]=1, redis.del
   *   T1: would SET cache to N (stale!) — but genBefore(0) !== now(1), skip.
   *
   * Without this guard, the inflight SET could replant a stale value AFTER
   * the bust's DEL. With it, the SET is gated on "the world looked the
   * same before and after my read"; otherwise a future reader will repeat
   * the DB hop and observe the post-bump value.
   */
  private readonly bustGen = new Map<string, number>();

  constructor(
    private readonly db: DbService,
    private readonly config: ConfigService,
  ) {}

  onModuleInit(): void {
    const url = this.config.get<string>("REDIS_URL") ?? process.env.REDIS_URL ?? "redis://localhost:6379";
    this.redis = new Redis(url, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableOfflineQueue: false,
      retryStrategy: (times) => Math.min(times * 200, 2000),
    });
    this.redis.on("error", (err) => {
      this.logger.warn({ err: err.message }, "session-epoch cache redis error");
    });

    const ttlRaw = this.config.get<string>("SESSION_EPOCH_CACHE_TTL") ?? process.env.SESSION_EPOCH_CACHE_TTL;
    const n = ttlRaw ? Number.parseInt(ttlRaw, 10) : NaN;
    this.cacheTtlSec = Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL_SEC;
    this.logger.log(`SessionEpochCache ready (ttl=${this.cacheTtlSec.toString()}s)`);
  }

  async onModuleDestroy(): Promise<void> {
    try {
      this.redis.disconnect();
    } catch (err) {
      this.logger.warn({ err }, "session-epoch cache disconnect failed");
    }
    return Promise.resolve();
  }

  /**
   * Resolve the current epoch for `userId`. Cache hit → O(1). Cache miss →
   * single DB read coalesced across concurrent callers via `inflight`.
   * Redis outage → falls back to a direct DB read.
   */
  async get(userId: string): Promise<number> {
    const key = KEY_PREFIX + userId;

    // Fast path: cache hit.
    try {
      const cached = await this.redis.get(key);
      if (cached !== null) {
        const parsed = Number.parseInt(cached, 10);
        if (Number.isFinite(parsed) && parsed >= 0) return parsed;
      }
    } catch (err) {
      this.logger.warn({ err: (err as Error).message, userId }, "session-epoch cache get failed");
    }

    // Cold path. Coalesce concurrent callers for the same userId.
    let inflight = this.inflight.get(userId);
    if (!inflight) {
      const genBefore = this.bustGen.get(userId) ?? 0;
      inflight = (async (): Promise<number> => {
        const epoch = await this.readDb(userId);
        // Generation guard — see `bustGen` jsdoc. If a bust raced through
        // during our DB hop, skip the SET so we don't replant a stale value
        // after the writer's DEL. The next reader repeats the DB hop and
        // observes the post-bump value.
        const genNow = this.bustGen.get(userId) ?? 0;
        if (genNow !== genBefore) {
          return epoch;
        }
        try {
          await this.redis.set(key, epoch.toString(), "EX", this.cacheTtlSec);
        } catch (err) {
          this.logger.warn({ err: (err as Error).message, userId }, "session-epoch cache set failed");
        }
        return epoch;
      })().finally(() => {
        this.inflight.delete(userId);
      });
      this.inflight.set(userId, inflight);
    }
    return inflight;
  }

  /**
   * Invalidate the cached epoch for `userId`. Call AFTER the DB UPDATE has
   * committed; the next reader will repopulate the cache from the DB.
   * Idempotent + Redis-outage-safe.
   */
  async bust(userId: string): Promise<void> {
    // Bump the generation FIRST so any concurrent inflight handler that's
    // still mid-DB-read will observe the change and skip its post-read SET.
    this.bustGen.set(userId, (this.bustGen.get(userId) ?? 0) + 1);
    const key = KEY_PREFIX + userId;
    try {
      await this.redis.del(key);
    } catch (err) {
      // Cache stays stale until TTL — but the next /me hit AFTER TTL expiry
      // will pick up the new epoch. Log so an operator knows to investigate.
      this.logger.warn({ err: (err as Error).message, userId }, "session-epoch cache del failed");
    }
  }

  private async readDb(userId: string): Promise<number> {
    const rows = await this.db.db
      .select({ e: schema.users.sessionEpoch })
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .limit(1);
    return rows[0]?.e ?? 0;
  }
}
