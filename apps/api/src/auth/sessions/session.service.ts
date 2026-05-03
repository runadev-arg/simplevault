import { createHash, createHmac, randomBytes } from "node:crypto";

import { HttpException, HttpStatus, Injectable, Logger, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { and, eq, isNull, sql } from "drizzle-orm";

import { DbService } from "../../db/db.service.js";

import { SessionEpochCache } from "./session-epoch.cache.js";

export interface IssuedRefreshToken {
  /** raw token, base64url — set as cookie value, never stored. */
  rawToken: string;
  sessionId: string;
  familyId: string;
  userId: string;
  expiresAt: Date;
}

interface RotateOk {
  kind: "ok";
  next: IssuedRefreshToken;
}
interface RotateInvalid {
  kind: "invalid";
}
interface RotateReuse {
  kind: "reuse";
  userId: string;
  familyId: string;
}
export type RotateResult = RotateOk | RotateInvalid | RotateReuse;

const REFRESH_TOKEN_BYTES = 32;

/**
 * Refresh-token lifecycle.
 *
 * - **Create** on login: generate 32 random bytes -> base64url ; store
 *   BLAKE2b-256 hash. New `family_id`. Insert row.
 * - **Rotate** on /auth/refresh: SELECT ... FOR UPDATE ; if `used_at` set ->
 *   reuse-detect, family-revoke ; else INSERT new row + UPDATE old row
 *   (used_at + revoked_at) ; same `family_id`.
 * - **RevokeFamilyByToken** on /auth/logout: revoke every non-revoked row
 *   sharing the family.
 *
 * `refresh_token_hash` is BLAKE2b-256 — fast integrity hash because the raw
 * token is already 256-bit-entropy random; KDFs would waste cycles.
 *
 * `ip_hash` is HMAC-SHA256(SERVER_IP_HASH_SECRET, ip) — keyed so dumps don't
 * yield raw IPs. Falls back to plain SHA-256 if the secret isn't set
 * (logged on first use; production should set the secret).
 */
@Injectable()
export class SessionService implements OnModuleInit {
  private readonly logger = new Logger(SessionService.name);
  private refreshTtlMs!: number;
  private ipHashSecret: Buffer | null = null;

  constructor(
    private readonly db: DbService,
    private readonly config: ConfigService,
    private readonly epochCache: SessionEpochCache,
  ) {}

  onModuleInit(): void {
    const ttlRaw = this.config.get<string>("REFRESH_TOKEN_TTL") ?? process.env.REFRESH_TOKEN_TTL;
    const n = ttlRaw ? Number.parseInt(ttlRaw, 10) : NaN;
    // Default 30 days (2,592,000 seconds), per the truths' Max-Age=2592000.
    const seconds = Number.isFinite(n) && n > 0 ? n : 30 * 24 * 60 * 60;
    this.refreshTtlMs = seconds * 1000;

    const ipSecretRaw = this.config.get<string>("SERVER_IP_HASH_SECRET") ?? process.env.SERVER_IP_HASH_SECRET;
    if (ipSecretRaw && ipSecretRaw.length >= 16) {
      this.ipHashSecret = Buffer.from(ipSecretRaw, "utf8");
    } else {
      this.logger.warn("SERVER_IP_HASH_SECRET not set — falling back to unkeyed SHA-256 for ip_hash");
    }
  }

  refreshTtlSeconds(): number {
    return Math.floor(this.refreshTtlMs / 1000);
  }

  /** BLAKE2b-256 (32B). Node's crypto exposes it as 'blake2b512' only on some
   *  platforms; we use the canonical sha256 if blake2b is unavailable, with a
   *  log warning at boot. To stay universally compatible we use Node's
   *  `createHash("blake2b512")` truncated to 32B when available. */
  private static hashToken(rawToken: string): Buffer {
    // blake2b512 is universally available in Node 22; truncate to 32B for
    // BLAKE2b-256 equivalence.
    try {
      return createHash("blake2b512").update(rawToken).digest().subarray(0, 32);
    } catch {
      // Last-ditch fallback — should never trigger on Node 22.
      return createHash("sha256").update(rawToken).digest();
    }
  }

  hashIp(ip: string): Buffer {
    if (this.ipHashSecret) {
      return createHmac("sha256", this.ipHashSecret).update(ip).digest();
    }
    return createHash("sha256").update(ip).digest();
  }

  /** Coarse UA family parser (no full UA-parser dep). Best-effort, never throws. */
  parseUaFamily(ua: string | undefined): string {
    if (!ua) return "unknown";
    const u = ua.slice(0, 256);
    let browser = "Other";
    if (u.includes("Edg/")) browser = "Edge";
    else if (u.includes("Chrome/") && !/Chromium|Edg|OPR/.test(u)) browser = "Chrome";
    else if (u.includes("Firefox/")) browser = "Firefox";
    else if (u.includes("Safari/") && !u.includes("Chrome") && !u.includes("Chromium")) browser = "Safari";
    else if (/curl\//i.test(u)) browser = "curl";
    let os = "Other";
    if (u.includes("Windows")) os = "Windows";
    else if (u.includes("Mac OS X") || u.includes("Macintosh")) os = "Mac";
    else if (u.includes("Android")) os = "Android";
    else if (u.includes("iPhone") || u.includes("iPad")) os = "iOS";
    else if (u.includes("Linux")) os = "Linux";
    return `${browser}/${os}`;
  }

  static base64url(buf: Buffer): string {
    return buf.toString("base64url");
  }

  /** Login: insert a fresh root-of-family session row. */
  async createOnLogin(userId: string, ip: string, ua: string | undefined): Promise<IssuedRefreshToken> {
    const rawTokenBytes = randomBytes(REFRESH_TOKEN_BYTES);
    const rawToken = SessionService.base64url(rawTokenBytes);
    const refreshTokenHash = SessionService.hashToken(rawToken);
    const familyId = crypto.randomUUID();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + this.refreshTtlMs);
    const ipHash = this.hashIp(ip);
    const uaFamily = this.parseUaFamily(ua);

    const inserted = await this.db.db
      .insert(schema.userSessions)
      .values({
        userId,
        familyId,
        refreshTokenHash,
        expiresAt,
        userAgentFamily: uaFamily,
        ipHash,
      })
      .returning({ id: schema.userSessions.id });

    const row = inserted[0];
    if (!row) throw new Error("session insert returned no rows");

    return { rawToken, sessionId: row.id, familyId, userId, expiresAt };
  }

  /**
   * Refresh-rotation. Atomic in a single transaction with `SELECT ... FOR
   * UPDATE`. Returns one of three discriminated outcomes — controller maps
   * to HTTP semantics.
   */
  async rotate(rawToken: string, ip: string, ua: string | undefined): Promise<RotateResult> {
    const tokenHash = SessionService.hashToken(rawToken);

    return this.db.db.transaction(async (tx) => {
      const lockedRows = await tx.execute<{
        id: string;
        user_id: string;
        family_id: string;
        used_at: Date | null;
        revoked_at: Date | null;
        expires_at: Date;
      }>(
        sql`SELECT id, user_id, family_id, used_at, revoked_at, expires_at
            FROM ${schema.userSessions}
            WHERE refresh_token_hash = ${tokenHash}
            FOR UPDATE`,
      );
      const row = lockedRows.rows[0];
      if (!row) {
        return { kind: "invalid" } as const;
      }
      const now = new Date();

      if (row.used_at !== null) {
        // REUSE DETECTED — family revoke, fail closed.
        await tx
          .update(schema.userSessions)
          .set({ revokedAt: now })
          .where(and(eq(schema.userSessions.familyId, row.family_id), isNull(schema.userSessions.revokedAt)));
        return { kind: "reuse", userId: row.user_id, familyId: row.family_id } as const;
      }
      if (row.revoked_at !== null || new Date(row.expires_at) <= now) {
        return { kind: "invalid" } as const;
      }

      // Valid — rotate.
      const newRawBytes = randomBytes(REFRESH_TOKEN_BYTES);
      const newRaw = SessionService.base64url(newRawBytes);
      const newHash = SessionService.hashToken(newRaw);
      const newExpiresAt = new Date(now.getTime() + this.refreshTtlMs);
      const ipHash = this.hashIp(ip);
      const uaFamily = this.parseUaFamily(ua);

      const inserted = await tx
        .insert(schema.userSessions)
        .values({
          userId: row.user_id,
          familyId: row.family_id,
          refreshTokenHash: newHash,
          prevTokenId: row.id,
          expiresAt: newExpiresAt,
          userAgentFamily: uaFamily,
          ipHash,
        })
        .returning({ id: schema.userSessions.id });
      const newRow = inserted[0];
      if (!newRow) throw new Error("session insert returned no rows");

      await tx
        .update(schema.userSessions)
        .set({ usedAt: now, revokedAt: now })
        .where(eq(schema.userSessions.id, row.id));

      return {
        kind: "ok",
        next: {
          rawToken: newRaw,
          sessionId: newRow.id,
          familyId: row.family_id,
          userId: row.user_id,
          expiresAt: newExpiresAt,
        },
      } as const;
    });
  }

  /**
   * Phase 03 / Plan 04 — read the user's current `users.session_epoch`
   * via the Redis-cached `SessionEpochCache`. Use at every JWT-issuing
   * site so freshly-minted access tokens carry the latest epoch (any
   * /sessions/revoke-all bump becomes effective on the *next* request).
   */
  async getEpoch(userId: string): Promise<number> {
    return this.epochCache.get(userId);
  }

  /**
   * Phase 03 / Plan 04 — bump `users.session_epoch` for `userId` and
   * invalidate the cached entry. Call this from `/sessions/revoke-all`
   * (Plan 05) — single-session revoke (`DELETE /sessions/:id`) does NOT
   * call this (per Plan 04 Key Link 3 — bumping per single-session-revoke
   * would invalidate other valid sessions' access tokens for the same user).
   *
   * Ordering: UPDATE first (commits in the implicit transaction Postgres
   * wraps around `execute`), THEN DEL the cache. The opposite order would
   * race: DEL → reader repopulates from DB (still old) → UPDATE → cache
   * holds the stale value until TTL.
   */
  async bumpEpoch(userId: string): Promise<void> {
    await this.db.db.execute(sql`UPDATE ${schema.users} SET session_epoch = session_epoch + 1 WHERE id = ${userId}`);
    await this.epochCache.bust(userId);
  }

  /** Logout: family-revoke every non-revoked sibling of the presented token. */
  async revokeFamilyByToken(rawToken: string): Promise<{ userId: string; familyId: string } | null> {
    const tokenHash = SessionService.hashToken(rawToken);
    const rows = await this.db.db
      .select({ id: schema.userSessions.id, userId: schema.userSessions.userId, familyId: schema.userSessions.familyId })
      .from(schema.userSessions)
      .where(eq(schema.userSessions.refreshTokenHash, tokenHash))
      .limit(1);
    const row = rows[0];
    if (!row) return null;
    await this.db.db
      .update(schema.userSessions)
      .set({ revokedAt: new Date() })
      .where(and(eq(schema.userSessions.familyId, row.familyId), isNull(schema.userSessions.revokedAt)));
    return { userId: row.userId, familyId: row.familyId };
  }

  /**
   * Phase 03 / Plan 05 (Truth 11) — list active sessions for `userId` for the
   * `/sessions` UI. Returns one row per FAMILY (the latest non-revoked row by
   * `created_at desc`) — the rotation chain inflates the table with one row
   * per refresh, but UX-wise that's "one session". The representative row's
   * id is the one the controller will accept on `DELETE /sessions/:id`.
   *
   * `current: true` for the family that contains `currentSessionId` (the sid
   * claim from the caller's JWT — which is the most-recently-rotated row's
   * id). We mark the representative row of that family, NOT the row whose id
   * literally equals `currentSessionId` (after rotation those can differ).
   *
   * `ipHashB64Prefix` is the first 6 chars of base64(ip_hash). Operator
   * decision (Truth 11): enough for "I recognise this network" UX without
   * leaking the full hash to the browser. 6 chars × 6 bits/char = 36 bits;
   * collisions are tolerable here — this is UX context, not authn.
   */
  async listForUser(
    userId: string,
    currentSessionId: string,
  ): Promise<
    {
      id: string;
      createdAt: string;
      lastUsedAt: string;
      current: boolean;
      userAgentFamily: string;
      ipHashB64Prefix: string;
    }[]
  > {
    // DISTINCT ON (family_id) — pick the latest non-revoked row per family.
    // Drizzle doesn't expose DISTINCT ON natively, so we fall back to raw SQL.
    const result = await this.db.db.execute<{
      id: string;
      family_id: string;
      created_at: Date;
      used_at: Date | null;
      user_agent_family: string | null;
      ip_hash: Buffer | null;
    }>(sql`
      SELECT DISTINCT ON (family_id)
        id, family_id, created_at, used_at, user_agent_family, ip_hash
      FROM ${schema.userSessions}
      WHERE user_id = ${userId} AND revoked_at IS NULL
      ORDER BY family_id, created_at DESC
    `);

    // First find the family_id of `currentSessionId` (which may be ANY row in
    // the chain, not necessarily the representative). One small extra query
    // beats a join; this list is bounded by the number of active families.
    let currentFamilyId: string | null = null;
    if (currentSessionId) {
      const cur = await this.db.db
        .select({ familyId: schema.userSessions.familyId })
        .from(schema.userSessions)
        .where(and(eq(schema.userSessions.id, currentSessionId), eq(schema.userSessions.userId, userId)))
        .limit(1);
      currentFamilyId = cur[0]?.familyId ?? null;
    }

    const items = result.rows.map((r) => {
      const created = r.created_at instanceof Date ? r.created_at : new Date(r.created_at);
      const used = r.used_at ? (r.used_at instanceof Date ? r.used_at : new Date(r.used_at)) : null;
      const ipHashBuf = r.ip_hash
        ? Buffer.isBuffer(r.ip_hash)
          ? r.ip_hash
          : Buffer.from(r.ip_hash as unknown as ArrayBufferLike)
        : null;
      return {
        id: r.id,
        createdAt: created.toISOString(),
        lastUsedAt: (used ?? created).toISOString(),
        current: r.family_id === currentFamilyId,
        userAgentFamily: r.user_agent_family ?? "unknown",
        ipHashB64Prefix: ipHashBuf ? ipHashBuf.toString("base64").slice(0, 6) : "",
      };
    });

    // current pinned first; otherwise createdAt asc.
    items.sort((a, b) => {
      if (a.current !== b.current) return a.current ? -1 : 1;
      return a.createdAt.localeCompare(b.createdAt);
    });
    return items;
  }

  /**
   * Phase 03 / Plan 05 (Truth 12) — revoke the family containing `sessionId`
   * IFF the row belongs to `userId` (anti-enumeration: cross-user → null,
   * controller maps to 404 NOT 403). Family-revoke semantics: every
   * non-revoked row sharing the family is marked revoked.
   *
   * Does NOT bump the epoch (single-session-revoke is intentionally softer
   * than revoke-all — Plan 04 Key Link 3). Only `revokeAllForUser` bumps.
   *
   * Returns `{familyId, revokedCount}` on success, `null` on cross-user /
   * non-existent / already-revoked (callers must NOT distinguish — anti-
   * enumeration means the same 404 for all three).
   */
  async revokeOne(
    userId: string,
    sessionId: string,
  ): Promise<{ familyId: string; revokedCount: number } | null> {
    const owned = await this.db.db
      .select({ familyId: schema.userSessions.familyId })
      .from(schema.userSessions)
      .where(and(eq(schema.userSessions.id, sessionId), eq(schema.userSessions.userId, userId)))
      .limit(1);
    const row = owned[0];
    if (!row) return null;

    const result = await this.db.db.execute<{ id: string }>(sql`
      UPDATE ${schema.userSessions}
      SET revoked_at = now()
      WHERE family_id = ${row.familyId} AND revoked_at IS NULL
      RETURNING id
    `);
    const revokedCount = result.rows.length;
    if (revokedCount === 0) {
      // The family was already revoked between our SELECT and UPDATE. Treat as
      // not-found from the caller's perspective (anti-enumeration: no point
      // distinguishing "you owned it but it was already gone" from "you don't
      // own it" — the leaked bit is identical).
      return null;
    }
    return { familyId: row.familyId, revokedCount };
  }

  // `revokeAllForUser` lands in Plan 05 / T2 alongside the controller's
  // POST /sessions/revoke-all + audit-event extension.

  /** Throws 401 with the canonical AUTH_INVALID_CREDENTIALS shape. */
  static throw401(): never {
    throw new HttpException(
      { error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" } },
      HttpStatus.UNAUTHORIZED,
    );
  }

  static throwReused(): never {
    throw new HttpException(
      { error: { code: ErrorCodes.AUTH_REFRESH_REUSE_DETECTED, message: "Refresh token reused" } },
      HttpStatus.UNAUTHORIZED,
    );
  }
}
