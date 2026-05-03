import { Controller, HttpCode, HttpStatus, Logger, Post, Req, Res } from "@nestjs/common";
import { Throttle } from "@nestjs/throttler";
import type { Request, Response } from "express";

import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { RateLimits } from "../../common/throttler.config.js";
import { JwtService } from "../jwt/jwt.service.js";
import { SessionService } from "../sessions/session.service.js";

const REFRESH_COOKIE = "__Host-refresh";

@Controller("auth")
export class RefreshController {
  private readonly logger = new Logger(RefreshController.name);

  constructor(
    private readonly sessions: SessionService,
    private readonly jwt: JwtService,
  ) {}

  @Post("refresh")
  @HttpCode(HttpStatus.OK)
  @Throttle({ [RateLimits.refreshIp.name]: { limit: RateLimits.refreshIp.limit, ttl: RateLimits.refreshIp.ttl } })
  async refresh(@Req() req: Request, @Res({ passthrough: true }) res: Response): Promise<unknown> {
    const cookieHeader = req.headers.cookie ?? "";
    const raw = parseCookie(cookieHeader, REFRESH_COOKIE);
    const ip = req.ip ?? req.socket.remoteAddress ?? "unknown";
    const ua = req.headers["user-agent"];
    const ipHashB64 = this.sessions.hashIp(ip).toString("base64");
    const uaFamily = this.sessions.parseUaFamily(typeof ua === "string" ? ua : undefined);

    if (!raw) {
      AuditEventService.emit(this.logger, {
        action: AuditAction.RefreshFail,
        actorUserId: null,
        targetId: null,
        outcome: "fail",
        reason: "no_cookie",
        ipHashB64,
        uaFamily,
      });
      SessionService.throw401();
    }

    const result = await this.sessions.rotate(raw, ip, typeof ua === "string" ? ua : undefined);

    if (result.kind === "invalid") {
      AuditEventService.emit(this.logger, {
        action: AuditAction.RefreshFail,
        actorUserId: null,
        targetId: null,
        outcome: "fail",
        reason: "invalid",
        ipHashB64,
        uaFamily,
      });
      SessionService.throw401();
    }
    if (result.kind === "reuse") {
      AuditEventService.emit(this.logger, {
        action: AuditAction.RefreshReuseDetected,
        actorUserId: result.userId,
        targetId: result.userId,
        outcome: "fail",
        reason: "reuse_detected",
        ipHashB64,
        uaFamily,
        data: { familyId: result.familyId },
      });
      SessionService.throwReused();
    }

    const next = result.next;
    const accessToken = await this.jwt.signAccessToken({
      sub: next.userId,
      sid: next.sessionId,
      fam: next.familyId,
      // Phase 03 hand-off: Plan 04 replaces this stub with the user's
      // current `users.session_epoch` (Redis-cached).
      epoch: 0,
    });

    res.cookie(REFRESH_COOKIE, next.rawToken, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      path: "/",
      maxAge: this.sessions.refreshTtlSeconds() * 1000,
    });

    AuditEventService.emit(this.logger, {
      action: AuditAction.RefreshOk,
      actorUserId: next.userId,
      targetId: next.userId,
      outcome: "ok",
      ipHashB64,
      uaFamily,
      data: { familyId: next.familyId },
    });

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
