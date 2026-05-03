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

import { StepUpJwtService } from "./step-up-jwt.service.js";

/**
 * Express request augmented with the verified step-up principal. Downstream
 * `/2fa/*` controllers read `req.stepUp.sub` for the user-id.
 */
export interface StepUpRequest extends Request {
  stepUp: { sub: string; epoch: number };
}

/**
 * `Authorization: Bearer <stepUpJwt>` guard.
 *
 * Verifies the token via `StepUpJwtService.verify`, which asserts
 * `payload.purpose === "2fa-stepup"`. On any failure path (missing header,
 * malformed, bad signature, expired, wrong purpose), throws a uniform 401
 * with `AUTH_STEP_UP_REQUIRED`.
 *
 * Used by `/2fa/webauthn/begin-auth`, `/2fa/webauthn/finish-auth`, and
 * `/2fa/totp/verify` (Plan 03-03). NEVER use for `/me` or any vault route —
 * that's `JwtAuthGuard`'s job, and it explicitly rejects step-up tokens by
 * the `purpose` discriminator.
 */
@Injectable()
export class Require2FAStepUpGuard implements CanActivate {
  private readonly logger = new Logger(Require2FAStepUpGuard.name);

  constructor(private readonly stepUp: StepUpJwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<StepUpRequest>();
    const header = req.headers.authorization;
    const token = extractBearer(header);
    if (!token) {
      this.deny("missing_bearer");
    }

    try {
      const claims = await this.stepUp.verify(token);
      req.stepUp = { sub: claims.sub, epoch: claims.epoch };
      return true;
    } catch (err) {
      const reason = classifyJoseError(err);
      this.logger.debug({ evt: "stepup.guard.deny", reason }, "stepup.guard.deny");
      this.deny(reason);
    }
  }

  private deny(reason: string): never {
    void reason;
    throw new HttpException(
      { error: { code: ErrorCodes.AUTH_STEP_UP_REQUIRED, message: "Step-up authentication required" } },
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
