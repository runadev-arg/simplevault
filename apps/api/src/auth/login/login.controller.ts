import {
  BadRequestException,
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  HttpException,
  Post,
  Req,
  Res,
} from "@nestjs/common";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { Request, Response } from "express";

import { clientIpKey, FixedWindowRateLimiter } from "../../common/rate-limit.js";
import { CryptoService } from "../../crypto/crypto.service.js";
import { SessionService } from "../sessions/session.service.js";

import { LoginSchema } from "./login.dto.js";
import { LoginService } from "./login.service.js";

const REFRESH_COOKIE = "__Host-refresh";

@Controller("auth")
export class LoginController {
  // REQ-RATELIMIT-002: 5 / IP / 15min AND 10 / email / 15min sliding window.
  // 02-09 swaps for @nestjs/throttler+Redis.
  private readonly limiterIp = new FixedWindowRateLimiter(
    "auth.login.ip",
    Number.parseInt(process.env.LOGIN_IP_RATE_LIMIT ?? "5", 10) || 5,
    15 * 60 * 1000,
  );
  private readonly limiterEmail = new FixedWindowRateLimiter(
    "auth.login.email",
    Number.parseInt(process.env.LOGIN_EMAIL_RATE_LIMIT ?? "10", 10) || 10,
    15 * 60 * 1000,
  );

  constructor(
    private readonly loginSvc: LoginService,
    private readonly sessions: SessionService,
    private readonly crypto: CryptoService,
  ) {}

  /**
   * Public — returns the GLOBAL Argon2id params the client uses to compute
   * the login verifier. No per-user salt here (anti-enumeration). The
   * per-user `server_argon_salt` is returned in the 200 login response so
   * only a successful auth gets it.
   */
  @Get("params")
  params(): { argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 } } {
    return { argon2Params: this.crypto.argon2Params() };
  }

  @Post("login")
  @HttpCode(HttpStatus.OK)
  async login(@Body() body: unknown, @Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<unknown> {
    this.limiterIp.consume(clientIpKey(req));

    const parsed = LoginSchema.safeParse(body);
    if (!parsed.success) {
      throw new BadRequestException({
        error: { code: ErrorCodes.VALIDATION_FAILED, message: "Invalid request body" },
      });
    }

    // Per-email limiter — coarse keyed by lower(email) (already normalised by Zod).
    this.limiterEmail.consume(`em:${parsed.data.email}`);

    const ip = clientIpKey(req);
    const ua = req.headers["user-agent"];
    const result = await this.loginSvc.login(parsed.data, ip, typeof ua === "string" ? ua : undefined);
    if (!result) {
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
