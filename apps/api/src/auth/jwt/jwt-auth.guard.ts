import {
  type CanActivate,
  type ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from "@nestjs/common";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { Request } from "express";

import { JwtService } from "./jwt.service.js";

/**
 * Augmented Express request with the authenticated principal attached by the
 * guard. Downstream handlers read `req.user.id` etc.
 *
 * NOTE: `Phase 02` does NOT yet check session-revocation server-side. JWT
 * `exp` is the only freshness check; instant-revoke (session-epoch / per-user
 * version) is Phase 03's `REQ-AUTH-004`. Logout family-revokes the refresh
 * token, so a stolen access JWT survives only until `exp`.
 */
export interface AuthedRequest extends Request {
  user: { id: string; sessionId: string; familyId: string };
}

/**
 * `Authorization: Bearer <jwt>` guard.
 *
 * Verifies via `JwtService.verifyAccessToken` (HS256 + JWT_SECRET, jose). On
 * any failure path (missing header, malformed, bad signature, expired,
 * malformed claims), throws a uniform 401 mapped through
 * `AllExceptionsFilter` to `{ error: { code: E1001, ... } }`.
 *
 * Reused by `/me` and any future authenticated endpoint.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(private readonly jwt: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AuthedRequest>();
    const header = req.headers.authorization;
    const token = extractBearer(header);
    if (!token) {
      this.deny("missing_bearer");
    }

    try {
      const claims = await this.jwt.verifyAccessToken(token);
      req.user = { id: claims.sub, sessionId: claims.sid, familyId: claims.fam };
      return true;
    } catch (err) {
      const reason = classifyJoseError(err);
      this.logger.debug({ evt: "auth.guard.deny", reason }, "auth.guard.deny");
      this.deny(reason);
    }
  }

  private deny(reason: string): never {
    void reason; // logged at call site; method kept symmetric for future audit emission.
    throw new HttpException(
      { error: { code: ErrorCodes.AUTH_INVALID_CREDENTIALS, message: "Invalid credentials" } },
      HttpStatus.UNAUTHORIZED,
    );
  }
}

function extractBearer(header: string | string[] | undefined): string | null {
  if (!header) return null;
  const v = Array.isArray(header) ? header[0] : header;
  if (!v) return null;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(v);
  return m ? m[1] ?? null : null;
}

function classifyJoseError(err: unknown): string {
  if (err && typeof err === "object" && "code" in err) {
    const c = (err as { code?: unknown }).code;
    if (typeof c === "string") return c;
  }
  if (err instanceof Error) return err.name;
  return "unknown";
}
