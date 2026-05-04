import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  HttpException,
  Req,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { eq } from "drizzle-orm";

import { Public } from "../../auth/jwt/public.decorator.js";
import { RateLimits } from "../../common/throttler.config.js";
import { DbService } from "../../db/db.service.js";

import { Require2FAStepUpGuard, type StepUpRequest } from "./step-up.guard.js";

/**
 * Phase 03 Plan 10 — `GET /2fa/step-up-material`.
 *
 * **DEVIATION FROM PLAN.** The plan called out one new endpoint
 * (`GET /2fa/totp/credentials`) but completing TOTP step-up client-side
 * requires more than just the wrapped TOTP secrets — the client also
 * needs to derive `master_DEK` to decrypt those secrets, and the
 * 2FA-required login response (Plan 08) deliberately does NOT carry the
 * unwrap material (`userArgonSalt` + `argon2Params` + `wrappedMasterDek`).
 *
 * Rather than landing TWO new endpoints, we collapse them into ONE: this
 * endpoint returns ALL the material needed to complete a TOTP step-up:
 *   - userArgonSalt + argon2Params + wrappedMasterDek → derive master_DEK
 *     locally given the user's already-typed password + secret_key
 *     (preserved in the keyStore across the soft `/login` → `/login/2fa`
 *     navigation).
 *   - totpCredentials[] → the wrapped TOTP secrets the client decrypts
 *     with master_DEK, then runs RFC 6238 against to derive the candidate
 *     step submitted to /2fa/totp/verify.
 *
 * SECURITY:
 *   - Step-up token guarded — caller has already passed 1FA.
 *   - Returned material is the SAME the user would get from a 1FA-only
 *     login (Plan 02-08 LoginSessionResponseSchema fields). No new secret
 *     leakage.
 *   - WebAuthn step-up callers DO NOT need this endpoint (the WebAuthn
 *     ceremony is browser-native + server-verified; no master_DEK
 *     required). Calling it from the WebAuthn path is harmless but
 *     wasteful — the web client only invokes it when at least one TOTP
 *     credential is enrolled.
 *   - The `wrappedSecret` blob is the same on-the-wire shape as
 *     /2fa/totp/finish-register accepts (`nonce || ciphertext` packed
 *     base64). The client unpacks the first 24 bytes as nonce.
 *
 * Throttler: IP-keyed via the existing `2fa-verify-ip` ceiling (30/min) —
 * the endpoint is on the step-up auth path so the same anti-abuse
 * envelope applies.
 */
@Controller("2fa/step-up-material")
// Plan 09 — opt out of the global JwtAuthGuard; this route carries a
// step-up token, not an access token. Auth is provided by the
// Require2FAStepUpGuard below.
@Public()
@UseGuards(Require2FAStepUpGuard)
export class StepUpMaterialController {
  constructor(private readonly db: DbService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaVerifyIp.name]: {
      limit: RateLimits.twoFaVerifyIp.limit,
      ttl: RateLimits.twoFaVerifyIp.ttl,
    },
  })
  async get(@Req() req: StepUpRequest): Promise<{
    userArgonSalt: string;
    argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 };
    wrappedMasterDek: string;
    totpCredentials: {
      id: string;
      name: string;
      wrappedSecret: string;
      encryptedSecretAad: string;
    }[];
  }> {
    const userId = req.stepUp.sub;

    const userRows = await this.db.db
      .select({
        userArgonSalt: schema.users.userArgonSalt,
        argon2Params: schema.users.argon2Params,
        wrappedMasterDek: schema.users.wrappedMasterDek,
      })
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .limit(1);
    const user = userRows[0];
    if (!user) {
      // Step-up token sub points at a deleted user — collapse to uniform
      // 401 (anti-enumeration: identical envelope as a bad/expired token).
      throw new HttpException(
        { error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" } },
        HttpStatus.UNAUTHORIZED,
      );
    }

    const totpRows = await this.db.db
      .select({
        id: schema.totpCredentials.id,
        name: schema.totpCredentials.name,
        wrappedSecret: schema.totpCredentials.wrappedSecret,
        encryptedSecretAad: schema.totpCredentials.encryptedSecretAad,
        createdAt: schema.totpCredentials.createdAt,
      })
      .from(schema.totpCredentials)
      .where(eq(schema.totpCredentials.userId, userId));

    return {
      userArgonSalt: Buffer.from(user.userArgonSalt).toString("base64"),
      argon2Params: user.argon2Params as {
        memoryKiB: number;
        iterations: number;
        parallelism: 1;
      },
      wrappedMasterDek: Buffer.from(user.wrappedMasterDek).toString("base64"),
      totpCredentials: totpRows
        .sort((a, b) => a.createdAt.toISOString().localeCompare(b.createdAt.toISOString()))
        .map((r) => ({
          id: r.id,
          name: r.name,
          wrappedSecret: Buffer.from(r.wrappedSecret).toString("base64"),
          encryptedSecretAad: Buffer.from(r.encryptedSecretAad).toString("base64"),
        })),
    };
  }
}
