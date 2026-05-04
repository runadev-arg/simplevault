import {
  type CanActivate,
  type ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { ErrorCodes } from "@simplevault/shared/errors";
import type { Request } from "express";
import { decodeJwt } from "jose";

import { SessionEpochCache } from "../sessions/session-epoch.cache.js";

import { JwtService } from "./jwt.service.js";
import { IS_PUBLIC_KEY } from "./public.decorator.js";

/**
 * Augmented Express request with the authenticated principal attached by the
 * guard. Downstream handlers read `req.user.id` etc.
 *
 * Phase 03 / Plan 04 (Truth 14) — every authed request now ALSO compares the
 * JWT's `epoch` claim against the current `users.session_epoch` (Redis-cached
 * via `SessionEpochCache`, TTL 60s). Mismatch → 401 AUTH_SESSION_REVOKED.
 * This closes Phase 02's deferred REQ-AUTH-004 (instant access-token
 * revocation): `revoke-all` bumps the column + busts the cache, so any
 * outstanding token is rejected on its next request.
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

  constructor(
    private readonly jwt: JwtService,
    private readonly epochCache: SessionEpochCache,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Phase 03 / Plan 09 — `@Public()` opt-out short-circuits BEFORE any
    // bearer-token inspection. Required because this guard is registered
    // as APP_GUARD in `app.module.ts`, which means it runs against every
    // route — including the truly-public ones (/health, /auth/login,
    // /auth/refresh, /auth/logout, /auth/params, /auth/signup,
    // /invite/redeem) and the step-up routes that authenticate via
    // `Require2FAStepUpGuard` instead. Method-level `@Public()` overrides
    // any class-level value (NestJS `getAllAndOverride` semantics).
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    const req = context.switchToHttp().getRequest<AuthedRequest>();
    const header = req.headers.authorization;
    const token = extractBearer(header);
    if (!token) {
      this.deny("missing_bearer");
    }

    // Phase 03 — Key Link 5: reject any token that carries a `purpose` claim
    // (those are step-up tokens; they MUST NOT be accepted as access tokens).
    // Decode without verification to inspect the discriminator first; the full
    // signature/expiry verification happens immediately after via
    // `verifyAccessToken`.
    try {
      const unverified = decodeJwt(token);
      if (unverified.purpose !== undefined) {
        this.logger.debug(
          { evt: "auth.guard.deny", reason: "non_access_token_purpose" },
          "auth.guard.deny",
        );
        this.deny("non_access_token_purpose");
      }
    } catch (err) {
      // Malformed JWT → fall through to the standard verify path which will
      // raise the same uniform 401.
      void err;
    }

    let claims: Awaited<ReturnType<JwtService["verifyAccessToken"]>>;
    try {
      claims = await this.jwt.verifyAccessToken(token);
    } catch (err) {
      const reason = classifyJoseError(err);
      this.logger.debug({ evt: "auth.guard.deny", reason }, "auth.guard.deny");
      this.deny(reason);
    }

    // Phase 03 / Plan 04 — Truth 14: compare JWT `epoch` against current
    // `users.session_epoch` (Redis-cached, TTL 60s). Mismatch → AUTH_SESSION_REVOKED.
    // Single read per request via `SessionEpochCache.get` (cache hit path is O(1)
    // Redis GET; cold path coalesces concurrent callers to one DB query).
    const currentEpoch = await this.epochCache.get(claims.sub);
    if (claims.epoch !== currentEpoch) {
      this.logger.debug(
        { evt: "auth.guard.deny", reason: "session_revoked", sub: claims.sub },
        "auth.guard.deny",
      );
      throw new HttpException(
        { error: { code: ErrorCodes.AUTH_SESSION_REVOKED, message: "Session revoked" } },
        HttpStatus.UNAUTHORIZED,
      );
    }

    req.user = { id: claims.sub, sessionId: claims.sid, familyId: claims.fam };
    return true;
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
