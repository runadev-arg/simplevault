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
  params(): { argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 } } {
    return { argon2Params: this.crypto.argon2Params() };
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
