import { Controller, HttpCode, HttpStatus, Logger, Post, Req, Res } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { Request, Response } from "express";

import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { RateLimits } from "../../common/throttler.config.js";
import { SessionService } from "../sessions/session.service.js";

const REFRESH_COOKIE = "__Host-refresh";

@Controller("auth")
export class LogoutController {
  private readonly logger = new Logger(LogoutController.name);
  constructor(private readonly sessions: SessionService) {}

  @Post("logout")
  @HttpCode(HttpStatus.OK)
  @Throttle({ [RateLimits.logoutIp.name]: { limit: RateLimits.logoutIp.limit, ttl: RateLimits.logoutIp.ttl } })
  async logout(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<unknown> {
    const cookieHeader = req.headers.cookie ?? "";
    const raw = parseCookie(cookieHeader, REFRESH_COOKIE);

    let revoked: { userId: string; familyId: string } | null = null;
    if (raw) {
      revoked = await this.sessions.revokeFamilyByToken(raw);
    }

    // Clear the cookie regardless (idempotent).
    res.cookie(REFRESH_COOKIE, "", {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: 0,
    });

    if (revoked) {
      AuditEventService.emit(this.logger, {
        action: AuditAction.Logout,
        actorUserId: revoked.userId,
        targetId: revoked.userId,
        outcome: "ok",
        data: { familyId: revoked.familyId },
      });
    } else {
      AuditEventService.emit(this.logger, {
        action: AuditAction.Logout,
        actorUserId: null,
        targetId: null,
        outcome: "ok",
        reason: "no_session",
      });
    }
    return { ok: true };
  }
}

function parseCookie(header: string, name: string): string | null {
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    const k = part.slice(0, eq).trim();
    if (k !== name) continue;
    return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}
