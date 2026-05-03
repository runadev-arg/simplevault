/**
 * Phase 03 Plan 04 — session-epoch JWT claim invariant spec.
 *
 * RED in Task 1, GREEN by Task 2/3. Uses an in-memory fake Redis + a stub
 * DbService so the suite runs without Postgres or a real Redis container.
 * Real e2e validation lives in Plan 12 (Cypress + CI).
 *
 * Invariants (per 03-04-PLAN.md):
 *   1. JWT carries `epoch: number`.
 *   2. JwtAuthGuard reads epoch via the cache (single read per request).
 *   3. bumpEpoch + cache-bust → previously-issued token is rejected with AUTH_SESSION_REVOKED.
 *   4. Tokens issued AFTER bumpEpoch remain valid.
 *   5. Cache hit avoids DB.
 *   6. Concurrent cache misses coalesce to a single DB read (in-flight de-dup).
 *   7. bumpEpoch racing concurrent reads leaves cache holding the NEW epoch (not the old).
 *   8. bumpEpoch on user A does not affect user B's cache.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

import { JwtService } from "../src/auth/jwt/jwt.service.js";
import { JwtAuthGuard } from "../src/auth/jwt/jwt-auth.guard.js";
import { SessionEpochCache } from "../src/auth/sessions/session-epoch.cache.js";

type RowMap = Map<string, number>;

interface FakeRedis {
  store: Map<string, string>;
  get: (k: string) => Promise<string | null>;
  set: (k: string, v: string, _ex: "EX", _ttl: number) => Promise<"OK">;
  del: (k: string) => Promise<number>;
}

function makeFakeRedis(): FakeRedis {
  const store = new Map<string, string>();
  return {
    store,
    async get(k) {
      return store.has(k) ? (store.get(k) ?? null) : null;
    },
    async set(k, v) {
      store.set(k, v);
      return "OK" as const;
    },
    async del(k) {
      return store.delete(k) ? 1 : 0;
    },
  };
}

interface DbStub {
  rows: RowMap;
  selectCalls: { userId: string; ts: number }[];
  updateCalls: { userId: string; ts: number }[];
  // Mimic the shape the cache + service hit:
  db: {
    select: (cols: unknown) => {
      from: (_t: unknown) => {
        where: (_w: unknown) => {
          limit: (_n: number) => Promise<{ e: number }[]>;
        };
      };
    };
    execute: (q: { _userId?: string; _delta?: number; _kind?: "bump" }) => Promise<unknown>;
  };
  // Marker the caller passes through `eq()` so the stub knows which user the query is for.
  // The real impl uses drizzle's `eq(schema.users.id, userId)`; in tests we set `__nextUserId`
  // before each call.
  __nextUserId: string | null;
}

function makeDbStub(rows: RowMap): DbStub {
  const stub: DbStub = {
    rows,
    selectCalls: [],
    updateCalls: [],
    __nextUserId: null,
    db: {
      select(): {
        from: (_t: unknown) => { where: (_w: unknown) => { limit: (_n: number) => Promise<{ e: number }[]> } };
      } {
        return {
          from() {
            return {
              where(): { limit: (_n: number) => Promise<{ e: number }[]> } {
                return {
                  async limit() {
                    const userId = stub.__nextUserId;
                    stub.__nextUserId = null;
                    if (userId === null) {
                      // Fall back: no user marker. Return empty.
                      return [];
                    }
                    stub.selectCalls.push({ userId, ts: Date.now() });
                    // Snapshot the row value NOW (representing a snapshot read
                    // in the DB transaction); then sleep to simulate latency.
                    // This shape lets concurrent bumpEpoch races be observable:
                    // the bump updates `rows` after this snapshot but before
                    // the promise resolves — exactly the worst-case the
                    // cache-busting strategy must handle. The next reader must
                    // observe the post-bump value (because bust() DELs whatever
                    // the in-flight handler eventually writes).
                    const e = rows.get(userId) ?? 0;
                    await new Promise<void>((r) => setTimeout(r, 25));
                    return [{ e }];
                  },
                };
              },
            };
          },
        };
      },
      async execute(q) {
        // For bumpEpoch — see usage below.
        if (q._kind === "bump" && typeof q._userId === "string" && typeof q._delta === "number") {
          stub.updateCalls.push({ userId: q._userId, ts: Date.now() });
          rows.set(q._userId, (rows.get(q._userId) ?? 0) + q._delta);
        }
        return undefined;
      },
    },
  };
  return stub;
}

/** Minimal ConfigService stub so JwtService.onModuleInit() works under test. */
function makeConfig(env: Record<string, string>): { get: (k: string) => string | undefined } {
  return {
    get(k: string) {
      return env[k];
    },
  };
}

const TEST_JWT_SECRET = "U".repeat(48); // 48 raw utf8 bytes ≥ 32 — accepted by JwtService
const USER_A = "11111111-1111-1111-1111-111111111111";
const USER_B = "22222222-2222-2222-2222-222222222222";

interface TestKit {
  jwt: JwtService;
  guard: JwtAuthGuard;
  cache: SessionEpochCache;
  db: DbStub;
  redis: FakeRedis;
  // helpers
  setUserMarker: (userId: string) => void;
  bumpEpoch: (userId: string) => Promise<void>;
}

async function makeKit(): Promise<TestKit> {
  const rows: RowMap = new Map([
    [USER_A, 0],
    [USER_B, 0],
  ]);
  const db = makeDbStub(rows);
  const redis = makeFakeRedis();

  const jwt = new JwtService(makeConfig({ JWT_SECRET: TEST_JWT_SECRET, ACCESS_TOKEN_TTL: "900" }) as never);
  jwt.onModuleInit();

  const cache = new SessionEpochCache(db as never, makeConfig({}) as never);
  // The cache exposes a private `redis` + `cacheTtlSec`; we install our fake.
  // This avoids a real network connection without changing production code.
  // (Same pattern Plan 02-08's session.service tests will use.)
  (cache as unknown as { redis: FakeRedis }).redis = redis;
  (cache as unknown as { cacheTtlSec: number }).cacheTtlSec = 60;
  // Wire user marker so the stub's select() can resolve which user it's reading.
  (cache as unknown as { __resolveUserId: (userId: string) => void }).__resolveUserId = (userId: string): void => {
    db.__nextUserId = userId;
  };

  const guard = new JwtAuthGuard(jwt, cache);

  // bumpEpoch helper — mirrors what session.service.bumpEpoch will do.
  async function bumpEpoch(userId: string): Promise<void> {
    await db.db.execute({ _kind: "bump", _userId: userId, _delta: 1 });
    await cache.bust(userId);
  }

  function setUserMarker(userId: string): void {
    db.__nextUserId = userId;
  }

  return { jwt, guard, cache, db, redis, setUserMarker, bumpEpoch };
}

/** Minimal ExecutionContext stub for guard.canActivate(). */
function ctxWithBearer(token: string): {
  switchToHttp: () => { getRequest: () => { headers: { authorization: string }; user?: unknown } };
} {
  const req: { headers: { authorization: string }; user?: unknown } = {
    headers: { authorization: `Bearer ${token}` },
  };
  return {
    switchToHttp: () => ({
      getRequest: () => req,
    }),
  };
}

describe("session-epoch JWT claim + guard", () => {
  let kit: TestKit;

  beforeEach(async () => {
    kit = await makeKit();
  });

  it("(1) signs an `epoch` claim into access tokens", async () => {
    const token = await kit.jwt.signAccessToken({
      sub: USER_A,
      sid: "00000000-0000-0000-0000-000000000001",
      fam: "00000000-0000-0000-0000-000000000002",
      epoch: 0,
    });
    const claims = await kit.jwt.verifyAccessToken(token);
    expect(claims.epoch).toBe(0);
    expect(claims.sub).toBe(USER_A);
  });

  it("(2) guard rejects token whose epoch differs from current", async () => {
    // Sign at epoch 0 → bump to 1 → present token → 401 AUTH_SESSION_REVOKED.
    const token = await kit.jwt.signAccessToken({
      sub: USER_A,
      sid: "s",
      fam: "f",
      epoch: 0,
    });
    await kit.bumpEpoch(USER_A);
    kit.setUserMarker(USER_A);

    await expect(kit.guard.canActivate(ctxWithBearer(token) as never)).rejects.toMatchObject({
      response: { error: { code: "E1017" } },
      status: 401,
    });
  });

  it("(3) guard accepts token signed AFTER bumpEpoch", async () => {
    await kit.bumpEpoch(USER_A);
    // Mint with the NEW epoch value. In production the signing site reads it
    // via SessionService.getEpoch; here we just look up our stub directly.
    const newEpoch = kit.db.rows.get(USER_A) ?? 0;
    const token = await kit.jwt.signAccessToken({
      sub: USER_A,
      sid: "s",
      fam: "f",
      epoch: newEpoch,
    });
    kit.setUserMarker(USER_A);

    await expect(kit.guard.canActivate(ctxWithBearer(token) as never)).resolves.toBe(true);
  });

  it("(4) cache hit avoids DB read", async () => {
    // Warm cache.
    kit.setUserMarker(USER_A);
    await kit.cache.get(USER_A);
    expect(kit.db.selectCalls.length).toBe(1);

    // Second call — should NOT hit DB.
    await kit.cache.get(USER_A);
    expect(kit.db.selectCalls.length).toBe(1);
  });

  it("(5) concurrent cold-cache reads coalesce to a single DB call", async () => {
    // Pre-set the marker so the FIRST select() picks the right user id; the
    // in-flight Map ensures only one query fires regardless.
    kit.setUserMarker(USER_A);

    const promises = Array.from({ length: 50 }, () => kit.cache.get(USER_A));
    const results = await Promise.all(promises);
    expect(results.every((r) => r === 0)).toBe(true);
    expect(kit.db.selectCalls.length).toBe(1);
  });

  it("(6) bumpEpoch racing concurrent reads — final cache holds the new epoch", async () => {
    // Cold cache. Start 20 concurrent reads.
    kit.setUserMarker(USER_A);
    const reads = Array.from({ length: 20 }, () => kit.cache.get(USER_A));
    // While reads are inflight (they have a 5ms artificial latency in the
    // stub), bump the epoch + bust.
    await new Promise<void>((r) => setTimeout(r, 1));
    await kit.bumpEpoch(USER_A);

    await Promise.all(reads);

    // After the dust settles: a fresh read MUST observe the new epoch (not 0).
    kit.setUserMarker(USER_A);
    const fresh = await kit.cache.get(USER_A);
    expect(fresh).toBe(1);
    // And the cache (Redis) must NOT be holding the stale value.
    const cached = kit.redis.store.get(`session-epoch:${USER_A}`);
    if (cached !== undefined) expect(cached).toBe("1");
  });

  it("(7) bumpEpoch on user A does not bust user B's cache", async () => {
    // Warm both.
    kit.setUserMarker(USER_A);
    await kit.cache.get(USER_A);
    kit.setUserMarker(USER_B);
    await kit.cache.get(USER_B);
    const callsBefore = kit.db.selectCalls.length;

    await kit.bumpEpoch(USER_A);

    // B's cache untouched: read again, no DB call.
    const b = await kit.cache.get(USER_B);
    expect(b).toBe(0);
    expect(kit.db.selectCalls.length).toBe(callsBefore);
  });

  it("(8) guard reads epoch exactly once per request (cache hit)", async () => {
    // Warm cache.
    kit.setUserMarker(USER_A);
    await kit.cache.get(USER_A);
    const callsAfterWarm = kit.db.selectCalls.length;

    const token = await kit.jwt.signAccessToken({
      sub: USER_A,
      sid: "s",
      fam: "f",
      epoch: 0,
    });
    await kit.guard.canActivate(ctxWithBearer(token) as never);
    expect(kit.db.selectCalls.length).toBe(callsAfterWarm); // pure cache hit
  });
});
