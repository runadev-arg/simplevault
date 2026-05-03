import { createHash, randomBytes } from "node:crypto";

import { HttpException, HttpStatus, Injectable, Logger } from "@nestjs/common";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { and, eq, lt, sql } from "drizzle-orm";

import { DbService } from "../../db/db.service.js";
import { RedisService } from "../../redis/redis.service.js";

import type {
  TotpFinishRegisterDto,
  TotpFinishRegisterResponse,
  TotpVerifyDto,
} from "./totp.dto.js";

/**
 * Issuance-nonce TTL (Plan 03 Key Link 3 — finish-register MUST prove
 * begin-register preceded it). 120s is generous enough for the user to
 * scan the QR + type their first 6-digit code.
 */
const ISSUANCE_TTL_SEC = 120;
const ISSUANCE_NONCE_BYTES = 32;

/**
 * TOTP enrolment + verification — server-side primitives.
 *
 * SECURITY INVARIANTS (LOAD-BEARING):
 *
 * 1. **Server never sees the TOTP plaintext.** This file imports NOTHING
 *    from `@simplevault/crypto/browser` (the only barrel that exposes
 *    `computeTotpStep` / `verifyTotpCandidate` / `buildOtpauthUrl`).
 *    The wrapped blob + AAD bytes are stored verbatim in
 *    `totp_credentials.{wrapped_secret, encrypted_secret_aad}`. The
 *    server does ZERO RFC 6238 arithmetic.
 *
 * 2. **Replay guard is atomic compare-and-swap.** `/2fa/totp/verify`
 *    runs a single `UPDATE ... WHERE last_used_step < $cs RETURNING id`.
 *    Zero rows updated -> 401 AUTH_2FA_TOTP_REPLAY. Two simultaneous
 *    verifies of the same step: exactly one wins. Never read-then-
 *    write — the server's only TOCTOU-free primitive is the SQL UPDATE
 *    itself.
 *
 * 3. **Issuance nonce.** `begin-register` mints a 32-byte random
 *    `issuanceNonce`, stores `sha256(nonce) -> userId` in Redis with
 *    TTL=120s, and returns `{issuanceNonce}`. `finish-register` runs
 *    `GETDEL` on the same key — returns the bound user-id and atomically
 *    burns the cache entry. Without the nonce, an attacker who's
 *    already 1FA'd could inject an arbitrary wrapped secret without ever
 *    going through the begin-register browser flow.
 *
 * 4. **Registration-step burn.** finish-register persists
 *    `last_used_step = candidateStep` so the very same code the user
 *    typed at enrolment time is also burned. An attacker who reads the
 *    finish-register POST cannot replay its `candidateStep`.
 */
@Injectable()
export class TotpService {
  private readonly logger = new Logger(TotpService.name);

  constructor(
    private readonly db: DbService,
    private readonly redis: RedisService,
  ) {
    // Reference logger to satisfy noUnusedLocals until 03-03 wires audit
    // emission. Plan 03-02 cross-plan unblock fix.
    void this.logger;
  }

  // ---------------------------------------------------------------- helpers

  private static issuanceKey(nonce: string): string {
    // Hash the nonce before using it as a Redis key so a Redis dump never
    // yields the live token. SHA-256 is fine — pre-image resistance is the
    // property we want; we never compare nonces (we just GETDEL).
    const h = createHash("sha256").update(nonce).digest("base64url");
    return `totp:issuance:${h}`;
  }

  private throw401Replay(): never {
    throw new HttpException(
      { error: { code: ErrorCodes.AUTH_2FA_TOTP_REPLAY, message: "TOTP code already used" } },
      HttpStatus.UNAUTHORIZED,
    );
  }

  private throw400IssuanceInvalid(): never {
    throw new HttpException(
      { error: { code: ErrorCodes.AUTH_2FA_TOTP_ISSUANCE_INVALID, message: "TOTP issuance nonce invalid or expired" } },
      HttpStatus.BAD_REQUEST,
    );
  }

  // ---------------------------------------------------------------- begin

  /**
   * Mint a single-use issuance nonce bound to `userId`. Output is intended
   * to flow back into `finishRegister` exactly once.
   */
  async beginRegister(userId: string): Promise<{ issuanceNonce: string }> {
    const issuanceNonce = randomBytes(ISSUANCE_NONCE_BYTES).toString("base64url");
    const key = TotpService.issuanceKey(issuanceNonce);
    // SET ... EX 120 NX — NX so duplicate keys (extraordinarily unlikely
    // collision) never silently overwrite an in-flight enrolment.
    const stored = await this.redis.client.set(key, userId, "EX", ISSUANCE_TTL_SEC, "NX");
    if (stored !== "OK") {
      throw new HttpException(
        { error: { code: ErrorCodes.SERVER_INTERNAL, message: "issuance nonce write failed" } },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
    return { issuanceNonce };
  }

  // ---------------------------------------------------------------- finish

  /**
   * Consume the issuance nonce atomically (`GETDEL`), persist the wrapped
   * secret, and burn the registration code by seeding `last_used_step =
   * candidateStep`.
   */
  async finishRegister(
    userId: string,
    dto: TotpFinishRegisterDto,
  ): Promise<TotpFinishRegisterResponse> {
    const key = TotpService.issuanceKey(dto.issuanceNonce);
    // Redis 6.2+ ships GETDEL natively — Dokploy ships Redis 7. ioredis
    // exposes it as `getdel` (lowercase camel for ioredis). Returns the
    // string value AND deletes the key in one atomic op.
    const boundUserId = await this.redis.client.getdel(key);
    if (!boundUserId || boundUserId !== userId) {
      this.throw400IssuanceInvalid();
    }

    const inserted = await this.db.db
      .insert(schema.totpCredentials)
      .values({
        userId,
        wrappedSecret: dto.wrappedSecret,
        encryptedSecretAad: dto.encryptedSecretAad,
        // Burn the candidate step so an attacker who captured this finish
        // POST cannot replay the same 6-digit code at /verify.
        lastUsedStep: dto.candidateStep,
        name: dto.name,
      })
      .returning({
        id: schema.totpCredentials.id,
        name: schema.totpCredentials.name,
      });

    const row = inserted[0];
    if (!row) {
      throw new HttpException(
        { error: { code: ErrorCodes.SERVER_INTERNAL, message: "totp insert returned no rows" } },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
    return { id: row.id, name: row.name };
  }

  // ---------------------------------------------------------------- verify

  /**
   * Atomic replay-guard CAS. Returns `{credentialId, userId}` on success
   * (caller mints a full session). Throws 401 AUTH_2FA_TOTP_REPLAY if the
   * candidate step is not strictly greater than `last_used_step`.
   *
   * IMPORTANT: this is the ONLY write path that advances `last_used_step`.
   * Any future "TOTP setting" endpoint that changes name etc. MUST NOT
   * touch `last_used_step` — only the verify path.
   */
  async verify(
    userId: string,
    dto: TotpVerifyDto,
  ): Promise<{ credentialId: string }> {
    const updated = await this.db.db
      .update(schema.totpCredentials)
      .set({
        lastUsedStep: dto.candidateStep,
        lastUsedAt: sql`now()`,
      })
      .where(
        and(
          eq(schema.totpCredentials.id, dto.credentialId),
          eq(schema.totpCredentials.userId, userId),
          lt(schema.totpCredentials.lastUsedStep, dto.candidateStep),
        ),
      )
      .returning({ id: schema.totpCredentials.id });

    const row = updated[0];
    if (!row) {
      // Could be: wrong credentialId, wrong userId (anti-enumeration —
      // same 401 either way), OR replay (candidate <= stored). All paths
      // collapse to the same uniform error.
      this.throw401Replay();
    }
    return { credentialId: row.id };
  }
}
