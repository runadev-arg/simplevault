import { Injectable, Logger, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { jwtVerify, SignJWT } from "jose";

import { JwtService } from "../../auth/jwt/jwt.service.js";

const KID = "primary";
const ALG = "HS256";

/**
 * Step-up token claims.
 *
 * SECURITY (Phase 03 — Key Link 5):
 * The step-up token is signed with the SAME `JWT_SECRET` as the regular
 * access token, but the `purpose:"2fa-stepup"` claim makes it a distinct
 * token kind. `JwtAuthGuard` (access-token verifier) rejects any token
 * where `payload.purpose !== undefined`, so a step-up token cannot
 * impersonate an access token. Conversely, this verifier asserts
 * `payload.purpose === "2fa-stepup"` and refuses anything else.
 *
 * Step-up tokens NEVER carry `sid` or `fam` — only the user-id and the
 * session-epoch the original 1FA pass observed. They are a one-shot
 * authorisation to call `/2fa/*` endpoints; on success, the relevant
 * `/finish-*` (or `/2fa/totp/verify`) endpoint mints a fresh
 * `__Host-refresh` cookie + access token like a normal Phase-02 login.
 */
export interface StepUpClaims {
  sub: string;
  purpose: "2fa-stepup";
  /** Session-epoch observed at 1FA pass. Replayed into the access JWT after 2FA. */
  epoch: number;
  iat: number;
  exp: number;
}

const DEFAULT_TTL_SEC = 120;

/**
 * Signer/verifier for the 2FA step-up token. Mirrors `JwtService` shape but:
 *   - shorter TTL (default 120s, env `STEP_UP_TOKEN_TTL`)
 *   - `purpose:"2fa-stepup"` claim discriminator
 *   - NO `sid` / `fam` (single-use authorisation, not a session reference)
 */
@Injectable()
export class StepUpJwtService implements OnModuleInit {
  private readonly logger = new Logger(StepUpJwtService.name);
  private secret!: Uint8Array;
  private ttlSec!: number;

  constructor(
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  onModuleInit(): void {
    this.secret = this.jwt.exposeSecret();
    const raw = this.config.get<string>("STEP_UP_TOKEN_TTL") ?? process.env.STEP_UP_TOKEN_TTL;
    const n = raw ? Number.parseInt(raw, 10) : NaN;
    this.ttlSec = Number.isFinite(n) && n > 0 ? n : DEFAULT_TTL_SEC;
    this.logger.log(`StepUpJwtService ready (kid=${KID}, ttl=${this.ttlSec.toString()}s)`);
  }

  ttlSeconds(): number {
    return this.ttlSec;
  }

  async sign(userId: string, epoch: number): Promise<string> {
    return await new SignJWT({ purpose: "2fa-stepup", epoch })
      .setProtectedHeader({ alg: ALG, kid: KID })
      .setSubject(userId)
      .setIssuedAt()
      .setExpirationTime(`${this.ttlSec.toString()}s`)
      .sign(this.secret);
  }

  async verify(token: string): Promise<StepUpClaims> {
    const { payload } = await jwtVerify(token, this.secret, { algorithms: [ALG] });
    if (typeof payload.sub !== "string") {
      throw new Error("malformed step-up claims (sub)");
    }
    if (payload.purpose !== "2fa-stepup") {
      // Token signed with same secret but for a different purpose — refuse.
      throw new Error("malformed step-up claims (purpose)");
    }
    if (typeof payload.epoch !== "number") {
      throw new Error("malformed step-up claims (epoch)");
    }
    return {
      sub: payload.sub,
      purpose: "2fa-stepup",
      epoch: payload.epoch,
      iat: payload.iat ?? 0,
      exp: payload.exp ?? 0,
    };
  }
}
