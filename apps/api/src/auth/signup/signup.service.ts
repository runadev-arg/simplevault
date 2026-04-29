import { HttpException, HttpStatus, Injectable, Logger } from "@nestjs/common";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { and, eq, isNull, sql } from "drizzle-orm";

import { CryptoService } from "../../crypto/crypto.service.js";
import { DbService } from "../../db/db.service.js";

import type { SignupDto, SignupResponse } from "./signup.dto.js";

/**
 * Atomic signup: redeems the invite + creates the user in a single PG
 * transaction. Either both rows reach their final state or neither does
 * (Drizzle/`pg` rolls back on any thrown exception inside `db.transaction`).
 *
 * Race resolution: the invite row is locked `FOR UPDATE` to serialise two
 * concurrent signups against the same inviteId. If a second tx wins the
 * lock and finds `redeemed_at IS NOT NULL`, it 400-INVITE_INVALIDs out
 * (same external code as a not-found / expired invite — anti-enumeration).
 *
 * Email enumeration defence: a unique-violation on `users_email_lower_idx`
 * also collapses to the same external INVITE_INVALID 400. Internal logs
 * preserve the SIGNUP_DUPLICATE_EMAIL distinction.
 */
@Injectable()
export class SignupService {
  private readonly logger = new Logger(SignupService.name);

  constructor(
    private readonly db: DbService,
    private readonly crypto: CryptoService,
  ) {}

  async signup(input: SignupDto): Promise<SignupResponse> {
    // KDF-downgrade defence: enforced server-side, not trusted from the client.
    if (!this.crypto.validateArgon2ParamsAboveFloor(input.argon2Params)) {
      this.logger.warn(
        { evt: "auth.signup.fail", reason: "kdf_downgrade", invite_id: input.inviteId },
        "signup fail",
      );
      throw new HttpException(
        { error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" } },
        HttpStatus.BAD_REQUEST,
      );
    }

    const recoveryHmac = this.crypto.outerRecoveryHmac(input.recoveryInnerHash);
    const serverArgonSalt = this.crypto.defaultServerArgonSalt();

    let userId: string;
    let email: string;
    let createdAt: Date;

    try {
      const result = await this.db.db.transaction(async (tx) => {
        // 1. Lock the invite row.
        const lockedRows = await tx.execute<{
          id: string;
          email: string;
          expires_at: Date;
          redeemed_at: Date | null;
        }>(
          sql`SELECT id, email, expires_at, redeemed_at
              FROM ${schema.inviteCodes}
              WHERE id = ${input.inviteId}
              FOR UPDATE`,
        );
        const row = lockedRows.rows[0];
        if (!row) {
          this.failInvalid("not_found", input.inviteId);
        }
        const now = new Date();
        if (new Date(row.expires_at) <= now) {
          this.failInvalid("expired", input.inviteId);
        }
        if (row.redeemed_at !== null) {
          this.failInvalid("already_redeemed", input.inviteId);
        }

        const inviteEmail = row.email; // already lowercased by CLI on insert.

        // 2. Insert the user.
        const insertedUsers = await tx
          .insert(schema.users)
          .values({
            email: inviteEmail,
            argon2SecretKeyHash: input.argon2SecretKeyHash,
            serverArgonSalt: serverArgonSalt,
            argon2Params: input.argon2Params,
            userArgonSalt: input.userArgonSalt,
            wrappedMasterDek: input.wrappedMasterDek,
            wrappedMasterDekRecovery: input.wrappedMasterDekRecovery,
            recoveryHmac,
            userPubKey: input.userPubKey,
            wrappedUserSigningSk: input.wrappedUserSigningSk,
            wrappedUserKxSk: input.wrappedUserKxSk,
          })
          .returning({ id: schema.users.id, email: schema.users.email, createdAt: schema.users.createdAt });

        const newUser = insertedUsers[0];
        if (!newUser) {
          throw new Error("user insert returned no rows");
        }

        // 3. Atomic redeem — single-shot UPDATE so concurrent winners race to 0 rows.
        const updated = await tx
          .update(schema.inviteCodes)
          .set({ redeemedAt: new Date(), redeemedUserId: newUser.id })
          .where(and(eq(schema.inviteCodes.id, row.id), isNull(schema.inviteCodes.redeemedAt)))
          .returning({ id: schema.inviteCodes.id });

        if (updated.length === 0) {
          // Lost the race — abort the tx (rolls back the user insert).
          this.failInvalid("race_lost", input.inviteId);
        }

        return newUser;
      });

      userId = result.id;
      email = result.email;
      createdAt = result.createdAt;
    } catch (err) {
      if (err instanceof HttpException) throw err;
      // Postgres unique-violation = 23505. Drizzle wraps as DrizzleQueryError
      // with the pg error on `.cause`; check both.
      const pgCode = pickPgCode(err);
      if (pgCode === "23505") {
        this.logger.warn(
          { evt: "auth.signup.fail", reason: "duplicate_email", code: ErrorCodes.AUTH_SIGNUP_DUPLICATE_EMAIL },
          "signup fail",
        );
        throw new HttpException(
          { error: { code: ErrorCodes.AUTH_INVITE_INVALID, message: "Invalid invite" } },
          HttpStatus.BAD_REQUEST,
        );
      }
      // Don't log the raw err object — its message + stack contain the
      // SQL params (bytea ciphertexts). Just log the bare type + first chars
      // of the message, never the stack.
      const errName = (err as { name?: unknown }).name;
      const errType = typeof errName === "string" ? errName : "Error";
      this.logger.error(
        { evt: "auth.signup.fail", reason: "internal", err_type: errType, pg_code: pgCode ?? null },
        "signup internal error",
      );
      throw new HttpException(
        { error: { code: ErrorCodes.SERVER_INTERNAL, message: "Internal server error" } },
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    this.logger.log(
      { evt: "signup", user_id: userId, email, ts: createdAt.toISOString() },
      "signup ok",
    );

    return { userId, email, createdAt: createdAt.toISOString() };
  }

  private failInvalid(reason: string, inviteId: string): never {
    this.logger.warn(
      { evt: "auth.signup.fail", reason, invite_id: inviteId, code: ErrorCodes.AUTH_INVITE_INVALID },
      "signup fail",
    );
    throw new HttpException(
      { error: { code: ErrorCodes.AUTH_INVITE_INVALID, message: "Invalid invite" } },
      HttpStatus.BAD_REQUEST,
    );
  }
}

function pickPgCode(err: unknown): string | undefined {
  if (typeof err !== "object" || err === null) return undefined;
  const e = err as { code?: unknown; cause?: unknown };
  if (typeof e.code === "string") return e.code;
  if (typeof e.cause === "object" && e.cause !== null) {
    const c = e.cause as { code?: unknown };
    if (typeof c.code === "string") return c.code;
  }
  return undefined;
}
