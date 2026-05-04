import {
  BadRequestException,
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  Res,
  UseGuards,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/types";
import type { Response } from "express";

import { Public } from "../../auth/jwt/public.decorator.js";
import { SessionService } from "../../auth/sessions/session.service.js";
import { RateLimits } from "../../common/throttler.config.js";
import { Require2FAStepUpGuard, type StepUpRequest } from "../step-up/step-up.guard.js";

import {
  WebauthnAuthService,
  type WebauthnFinishAuthResult,
} from "./webauthn-auth.service.js";
import { FinishAuthSchema } from "./webauthn.dto.js";

const REFRESH_COOKIE = "__Host-refresh";

interface FinishAuthResponseBody {
  accessToken: string;
  expiresIn: number;
  wrappedMasterDek: string;
  wrappedMasterDekRecovery: string;
  argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 };
  serverArgonSalt: string;
  userArgonSalt: string;
  userPubKey: string;
  wrappedUserSigningSk: string;
  wrappedUserKxSk: string;
}

// Plan 09 — class-level @Public() opts the begin-auth + finish-auth pair out
// of the global JwtAuthGuard. Both routes carry a step-up token instead of
// an access token, and Require2FAStepUpGuard provides the actual auth check.
@Controller("2fa/webauthn")
@Public()
@UseGuards(Require2FAStepUpGuard)
export class WebauthnAuthController {
  constructor(
    private readonly authSvc: WebauthnAuthService,
    private readonly sessions: SessionService,
  ) {}

  /**
   * `POST /2fa/webauthn/begin-auth` — emit assertion options.
   * Step-up token required: the request must carry
   * `Authorization: Bearer <stepUpJwt>` (purpose:"2fa-stepup"), issued by
   * /auth/login when the user has 2FA enabled.
   */
  @Post("begin-auth")
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaWebauthnAuthIp.name]: {
      limit: RateLimits.twoFaWebauthnAuthIp.limit,
      ttl: RateLimits.twoFaWebauthnAuthIp.ttl,
    },
  })
  async beginAuth(@Req() req: StepUpRequest): Promise<PublicKeyCredentialRequestOptionsJSON> {
    return await this.authSvc.beginAuth(req.stepUp.sub);
  }

  /**
   * `POST /2fa/webauthn/finish-auth` — verify assertion + mint full session.
   * On success, sets the same `__Host-refresh` cookie + body envelope as
   * a Phase-02 1FA-only login (so the web client's existing post-login
   * machinery just works).
   */
  @Post("finish-auth")
  @HttpCode(HttpStatus.OK)
  @Throttle({
    [RateLimits.twoFaWebauthnAuthIp.name]: {
      limit: RateLimits.twoFaWebauthnAuthIp.limit,
      ttl: RateLimits.twoFaWebauthnAuthIp.ttl,
    },
  })
  async finishAuth(
    @Req() req: StepUpRequest,
    @Body() body: unknown,
    @Res({ passthrough: true }) res: Response,
  ): Promise<FinishAuthResponseBody> {
    const parsed = FinishAuthSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }

    const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
    const ua = req.headers["user-agent"];

    const result: WebauthnFinishAuthResult = await this.authSvc.finishAuth(
      req.stepUp.sub,
      parsed.data.response as unknown as Parameters<
        WebauthnAuthService["finishAuth"]
      >[1],
      ip,
      typeof ua === "string" ? ua : undefined,
    );

    res.cookie(REFRESH_COOKIE, result.refresh.rawToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: this.sessions.refreshTtlSeconds() * 1000,
    });

    return {
      accessToken: result.accessToken,
      ...result.bodyExtras,
    };
  }
}
