import { Controller, HttpCode, HttpStatus, Logger, Post, Req, Res } from "@nestjs/common";
import type { Request, Response } from "express";

import { SessionService } from "../sessions/session.service.js";

const REFRESH_COOKIE = "__Host-refresh";

@Controller("auth")
export class LogoutController {
  private readonly logger = new Logger(LogoutController.name);
  constructor(private readonly sessions: SessionService) {}

  @Post("logout")
  @HttpCode(HttpStatus.OK)
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
      this.logger.log(
        { evt: "auth.logout", user_id: revoked.userId, family_id: revoked.familyId },
        "auth.logout",
      );
    } else {
      this.logger.log({ evt: "auth.logout", reason: "no_session" }, "auth.logout");
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
