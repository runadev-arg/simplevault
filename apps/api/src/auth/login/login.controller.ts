import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  HttpException,
  Logger,
  Post,
  Req,
  Res,
} from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { Request, Response } from "express";

import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { RateLimits } from "../../common/throttler.config.js";
import { CryptoService } from "../../crypto/crypto.service.js";
import { SessionService } from "../sessions/session.service.js";

import { LoginSchema } from "./login.dto.js";
import { LoginService } from "./login.service.js";

const REFRESH_COOKIE = "__Host-refresh";

@Controller("auth")
export class LoginController {
  private readonly logger = new Logger(LoginController.name);

  constructor(
    private readonly loginSvc: LoginService,
    private readonly sessions: SessionService,
    private readonly crypto: CryptoService,
  ) {}

  /**
   * Public — returns the GLOBAL Argon2id params the client uses to compute
   * the login verifier. No per-user salt here (anti-enumeration).
   */
  @Get("params")
  @Throttle({ [RateLimits.authParamsIp.name]: { limit: RateLimits.authParamsIp.limit, ttl: RateLimits.authParamsIp.ttl } })
  params(): {
    argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 };
    serverArgonSalt: string;
  } {
    // The client needs `serverArgonSalt` to compute `argon2_secret_key_hash`
    // BEFORE it has authenticated (chicken-and-egg). We expose the GLOBAL
    // server-argon-salt here. Per CRYPTO-STACK §2 + the planner's anti-
    // enumeration design (02-INDEX), the salt is a public-by-convention
    // operator-managed value (akin to a server-wide pepper in plain Argon2id
    // password schemes). It does NOT leak per-user existence.
    return {
      argon2Params: this.crypto.argon2Params(),
      serverArgonSalt: this.crypto.defaultServerArgonSalt().toString("base64"),
    };
  }

  @Post("login")
  @HttpCode(HttpStatus.OK)
  // Both IP and email keyed — REQ-RATELIMIT-002.
  @Throttle({
    [RateLimits.loginIp.name]: { limit: RateLimits.loginIp.limit, ttl: RateLimits.loginIp.ttl },
    [RateLimits.loginEmail.name]: { limit: RateLimits.loginEmail.limit, ttl: RateLimits.loginEmail.ttl },
  })
  async login(@Body() body: unknown, @Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<unknown> {
    const parsed = LoginSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }

    const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
    const ua = req.headers["user-agent"];
    const result = await this.loginSvc.login(parsed.data, ip, typeof ua === "string" ? ua : undefined);
    if (!result) {
      AuditEventService.emit(this.logger, {
        action: AuditAction.LoginFail,
        actorUserId: null,
        targetId: null,
        outcome: "fail",
        reason: "invalid_credentials",
        ipHashB64: this.sessions.hashIp(ip).toString("base64"),
        uaFamily: this.sessions.parseUaFamily(typeof ua === "string" ? ua : undefined),
      });
      throw new HttpException(
        { error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" } },
        HttpStatus.UNAUTHORIZED,
      );
    }

    // Phase 03 Plan 08 — branch on result.kind (Truth 8).
    //
    // 2FA-required: NO refresh cookie. The user has no refresh family yet;
    // the family is created by `/2fa/webauthn/finish-auth` or
    // `/2fa/totp/verify` after the 2FA ceremony completes.
    //
    // session: Phase-02 behaviour — set the `__Host-refresh` cookie and
    // return the existing 200 body byte-equal to pre-Plan-08 callers.
    if (result.kind === "2fa-required") {
      return result.body;
    }

    res.cookie(REFRESH_COOKIE, result.refresh.rawToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: this.sessions.refreshTtlSeconds() * 1000,
    });

    return result.body;
  }
}
