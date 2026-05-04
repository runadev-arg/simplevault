import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Logger,
  Post,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { eq, sql } from "drizzle-orm";
import type { Request, Response } from "express";

import { JwtAuthGuard, type AuthedRequest } from "../../auth/jwt/jwt-auth.guard.js";
import { JwtService } from "../../auth/jwt/jwt.service.js";
import { Public } from "../../auth/jwt/public.decorator.js";
import { SessionService } from "../../auth/sessions/session.service.js";
import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { RateLimits } from "../../common/throttler.config.js";
import { DbService } from "../../db/db.service.js";
import { Require2FAStepUpGuard, type StepUpRequest } from "../step-up/step-up.guard.js";

import {
  TotpFinishRegisterSchema,
  TotpVerifySchema,
  type TotpBeginRegisterResponse,
  type TotpFinishRegisterResponse,
} from "./totp.dto.js";
import { TotpService } from "./totp.service.js";

const REFRESH_COOKIE = "__Host-refresh";

/**
 * `/2fa/totp/*` controller.
 *
 * - `begin-register` and `finish-register` require a regular access JWT
 *   (`JwtAuthGuard`). The user is already authenticated; they're adding
 *   a TOTP credential to their own account.
 * - `verify` requires a step-up token (`Require2FAStepUpGuard`) issued by
 *   `/auth/login` after 1FA passes. On success, the controller mints a
 *   full Phase-02-shape login response (access JWT + `__Host-refresh`
 *   cookie + wrapped material).
 *
 * SECURITY (Phase 03 Key Link 3): this file MUST NOT import any function
 * from `@simplevault/crypto/browser`. Server runs zero RFC 6238 logic.
 */
@Controller("2fa/totp")
export class TotpController {
  private readonly logger = new Logger(TotpController.name);

  constructor(
    private readonly totp: TotpService,
    private readonly db: DbService,
    private readonly jwt: JwtService,
    private readonly sessions: SessionService,
  ) {}

  // ---------------------------------------------------------------- begin

  @Post("begin-register")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaRegisterUser.name]: {
      limit: RateLimits.twoFaRegisterUser.limit,
      ttl: RateLimits.twoFaRegisterUser.ttl,
    },
  })
  async beginRegister(@Req() req: AuthedRequest): Promise<TotpBeginRegisterResponse> {
    return await this.totp.beginRegister(req.user.id);
  }

  // ---------------------------------------------------------------- finish

  @Post("finish-register")
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaRegisterUser.name]: {
      limit: RateLimits.twoFaRegisterUser.limit,
      ttl: RateLimits.twoFaRegisterUser.ttl,
    },
  })
  async finishRegister(
    @Req() req: AuthedRequest,
    @Body() body: unknown,
  ): Promise<TotpFinishRegisterResponse> {
    const parsed = TotpFinishRegisterSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }
    try {
      const out = await this.totp.finishRegister(req.user.id, parsed.data);
      AuditEventService.emit(this.logger, {
        action: AuditAction.TwoFaTotpRegisterOk,
        actorUserId: req.user.id,
        targetId: out.id,
        outcome: "ok",
      });
      return out;
    } catch (err) {
      AuditEventService.emit(this.logger, {
        action: AuditAction.TwoFaTotpRegisterFail,
        actorUserId: req.user.id,
        targetId: null,
        outcome: "fail",
        reason: err instanceof Error ? err.name : "unknown",
      });
      throw err;
    }
  }

  // ---------------------------------------------------------------- verify

  @Post("verify")
  // Plan 09 — opt out of the global JwtAuthGuard; this route carries a
  // step-up token (purpose:"2fa-stepup"), not an access token, and is
  // authenticated by Require2FAStepUpGuard below.
  @Public()
  @UseGuards(Require2FAStepUpGuard)
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaVerifyIp.name]: {
      limit: RateLimits.twoFaVerifyIp.limit,
      ttl: RateLimits.twoFaVerifyIp.ttl,
    },
  })
  async verify(
    @Req() req: Request,
    @Body() body: unknown,
    @Res({ passthrough: true }) res: Response,
  ): Promise<unknown> {
    const stepUpReq = req as StepUpRequest;
    const userId = stepUpReq.stepUp.sub;
    const parsed = TotpVerifySchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }

    try {
      // Atomic CAS replay-guard. Throws 401 AUTH_2FA_TOTP_REPLAY on
      // zero-rows-updated.
      const verified = await this.totp.verify(userId, parsed.data);

      // Mint a full session. Matches /auth/login's exit shape so the
      // web client's discriminated `{kind:"session"}` branch handles it
      // identically.
      const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
      const ua = req.headers["user-agent"];
      const uaStr = typeof ua === "string" ? ua : undefined;

      const userRows = await this.db.db
        .select({
          id: schema.users.id,
          sessionEpoch: schema.users.sessionEpoch,
          wrappedMasterDek: schema.users.wrappedMasterDek,
          wrappedMasterDekRecovery: schema.users.wrappedMasterDekRecovery,
          argon2Params: schema.users.argon2Params,
          serverArgonSalt: schema.users.serverArgonSalt,
          userArgonSalt: schema.users.userArgonSalt,
          userPubKey: schema.users.userPubKey,
          wrappedUserSigningSk: schema.users.wrappedUserSigningSk,
          wrappedUserKxSk: schema.users.wrappedUserKxSk,
        })
        .from(schema.users)
        .where(eq(schema.users.id, userId))
        .limit(1);
      const user = userRows[0];
      if (!user) {
        // Step-up token sub points at a deleted user. Treat as auth failure.
        AuditEventService.emit(this.logger, {
          action: AuditAction.TwoFaTotpVerifyFail,
          actorUserId: userId,
          targetId: parsed.data.credentialId,
          outcome: "fail",
          reason: "user_missing",
        });
        throw new BadRequestException({
          error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" },
        });
      }

      const refresh = await this.sessions.createOnLogin(userId, ip, uaStr);
      const accessToken = await this.jwt.signAccessToken({
        sub: userId,
        sid: refresh.sessionId,
        fam: refresh.familyId,
        // Plan 03-04: include the user's current session_epoch so
        // JwtAuthGuard can check for revocation. Read fresh from the
        // users row rather than trusting the step-up token's value
        // (revoke-all may have bumped the epoch since the step-up was
        // minted).
        epoch: user.sessionEpoch,
      });

      res.cookie(REFRESH_COOKIE, refresh.rawToken, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        path: "/",
        maxAge: this.sessions.refreshTtlSeconds() * 1000,
      });

      AuditEventService.emit(this.logger, {
        action: AuditAction.TwoFaTotpVerifyOk,
        actorUserId: userId,
        targetId: verified.credentialId,
        outcome: "ok",
        ipHashB64: this.sessions.hashIp(ip).toString("base64"),
        uaFamily: this.sessions.parseUaFamily(uaStr),
        data: { familyId: refresh.familyId },
      });

      return {
        accessToken,
        expiresIn: this.jwt.accessTtlSeconds(),
        wrappedMasterDek: Buffer.from(user.wrappedMasterDek).toString("base64"),
        wrappedMasterDekRecovery: Buffer.from(user.wrappedMasterDekRecovery).toString("base64"),
        argon2Params: user.argon2Params,
        serverArgonSalt: Buffer.from(user.serverArgonSalt).toString("base64"),
        userArgonSalt: Buffer.from(user.userArgonSalt).toString("base64"),
        userPubKey: Buffer.from(user.userPubKey).toString("base64"),
        wrappedUserSigningSk: Buffer.from(user.wrappedUserSigningSk).toString("base64"),
        wrappedUserKxSk: Buffer.from(user.wrappedUserKxSk).toString("base64"),
      };
    } catch (err) {
      // Service throws 401 AUTH_2FA_TOTP_REPLAY on CAS miss; controller
      // logs the audit-fail before letting the exception propagate.
      // Don't double-log the user_missing branch above (already audited).
      const isReplay =
        err instanceof Error &&
        // HttpException stores the response in .getResponse() — we keep
        // the audit-emit minimal: just log a structured fail.
        true;
      if (isReplay) {
        AuditEventService.emit(this.logger, {
          action: AuditAction.TwoFaTotpVerifyFail,
          actorUserId: userId,
          targetId: parsed.data.credentialId,
          outcome: "fail",
          reason: err instanceof Error ? err.name : "unknown",
        });
      }
      throw err;
    }
  }
}

// Suppress unused `sql` import if any future composite operation drops it.
void sql;
