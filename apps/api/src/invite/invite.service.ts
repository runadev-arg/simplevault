import { HttpException, HttpStatus, Injectable, Logger } from "@nestjs/common";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { eq } from "drizzle-orm";

import { CryptoService } from "../crypto/crypto.service.js";
import { DbService } from "../db/db.service.js";

import type { InviteRedeemResponse } from "./invite.dto.js";

/**
 * Invite redemption — informational only. Returns the per-deployment
 * Argon2 params + server_argon_salt the client uses to compute the verifier
 * artifacts. Does NOT mark the code redeemed; only successful POST
 * /auth/signup atomically consumes the invite.
 *
 * Anti-enumeration: every failure mode (not-found / expired / already-redeemed)
 * returns the SAME external INVITE_INVALID 400. Internal logging keeps the
 * distinction. The response body shape on success and the error body shape
 * on every failure are constant — no field reveals which check failed.
 */
@Injectable()
export class InviteService {
  private readonly logger = new Logger(InviteService.name);

  constructor(
    private readonly db: DbService,
    private readonly crypto: CryptoService,
  ) {}

  async redeem(rawCode: string): Promise<InviteRedeemResponse> {
    const codeBytes = Buffer.from(rawCode, "utf8");
    const codeHash = this.crypto.inviteCodeHmac(codeBytes);

    const rows = await this.db.db
      .select()
      .from(schema.inviteCodes)
      .where(eq(schema.inviteCodes.codeHash, codeHash))
      .limit(1);

    const row = rows[0];
    if (!row) {
      this.logger.warn({ evt: "invite.redeem.fail", reason: "not_found" }, "invite redeem fail");
      this.throwInvalid();
    }
    const now = new Date();
    if (row.expiresAt <= now) {
      this.logger.warn(
        { evt: "invite.redeem.fail", reason: "expired", invite_id: row.id },
        "invite redeem fail",
      );
      this.throwInvalid();
    }
    if (row.redeemedAt !== null) {
      this.logger.warn(
        { evt: "invite.redeem.fail", reason: "already_redeemed", invite_id: row.id },
        "invite redeem fail",
      );
      this.throwInvalid();
    }

    const params = this.crypto.argon2Params();
    const serverArgonSalt = this.crypto.defaultServerArgonSalt();

    this.logger.log({ evt: "invite.redeem.ok", invite_id: row.id }, "invite redeem ok");

    return {
      inviteId: row.id,
      email: row.email,
      argon2Params: params,
      serverArgonSalt: serverArgonSalt.toString("base64"),
    };
  }

  private throwInvalid(): never {
    throw new HttpException(
      {
        error: { code: ErrorCodes.AUTH_INVITE_INVALID, message: "Invalid invite" },
      },
      HttpStatus.BAD_REQUEST,
    );
  }
}
