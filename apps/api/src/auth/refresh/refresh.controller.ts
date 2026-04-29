import { Controller, HttpCode, HttpStatus, Logger, Post, Req, Res } from "@nestjs/common";
import type { Request, Response } from "express";

import { clientIpKey, FixedWindowRateLimiter } from "../../common/rate-limit.js";
import { JwtService } from "../jwt/jwt.service.js";
import { SessionService } from "../sessions/session.service.js";

const REFRESH_COOKIE = "__Host-refresh";

@Controller("auth")
export class RefreshController {
  private readonly logger = new Logger(RefreshController.name);
  // 30 / IP / 15min — generous, legitimate clients refresh ~every 15min.
  private readonly limiter = new FixedWindowRateLimiter(
    "auth.refresh.ip",
    Number.parseInt(process.env.REFRESH_IP_RATE_LIMIT ?? "30", 10) || 30,
    15 * 60 * 1000,
  );

  constructor(
    private readonly sessions: SessionService,
    private readonly jwt: JwtService,
  ) {}

  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<unknown> {
    this.limiter.consume(clientIpKey(req));

    const cookieHeader = req.headers.cookie ?? "";
    const raw = parseCookie(cookieHeader, REFRESH_COOKIE);
    if (!raw) {
      this.logger.warn({ evt: "auth.refresh.fail", reason: "no_cookie" }, "auth.refresh.fail");
      SessionService.throw401();
    }

    const ip = clientIpKey(req);
    const ua = req.headers["user-agent"];
    const result = await this.sessions.rotate(raw, ip, typeof ua === "string" ? ua : undefined);

    if (result.kind === "invalid") {
      this.logger.warn({ evt: "auth.refresh.fail", reason: "invalid" }, "auth.refresh.fail");
      SessionService.throw401();
    }
    if (result.kind === "reuse") {
      this.logger.warn(
        {
          evt: "auth.refresh.reuse_detected",
          user_id: result.userId,
          family_id: result.familyId,
          ip_hash_b64: this.sessions.hashIp(ip).toString("base64"),
        },
        "auth.refresh.reuse_detected",
      );
      SessionService.throwReused();
    }

    const next = result.next;
    const accessToken = await this.jwt.signAccessToken({
      sub: next.userId,
      sid: next.sessionId,
      fam: next.familyId,
    });

    res.cookie(REFRESH_COOKIE, next.rawToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: this.sessions.refreshTtlSeconds() * 1000,
    });

    this.logger.log(
      { evt: "auth.refresh.ok", user_id: next.userId, family_id: next.familyId },
      "auth.refresh.ok",
    );

    return {
      accessToken,
      expiresIn: this.jwt.accessTtlSeconds(),
    };
  }
}

/** Tiny cookie parser — avoids adding `cookie-parser` middleware just for one read. */
function parseCookie(header: string, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (k !== name) continue;
    const v = part.slice(eq + 1).trim();
    return decodeURIComponent(v);
  }
  return null;
}
