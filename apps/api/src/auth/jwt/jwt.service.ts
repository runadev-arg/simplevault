import { Injectable, Logger, type OnModuleInit } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { jwtVerify, SignJWT } from "jose";

export interface AccessTokenClaims {
  /** user id (UUID) */
  sub: string;
  /** session id (UUID) — points at the user_sessions row that issued this token */
  sid: string;
  /** family id (UUID) — refresh-rotation lineage */
  fam: string;
  /**
   * session-epoch — `users.session_epoch` value at the moment the token was
   * minted. `JwtAuthGuard` compares this against the current per-user epoch
   * (Redis-cached, TTL 60s); mismatch → 401 AUTH_SESSION_REVOKED. Closes
   * Phase-02 deferred REQ-AUTH-004 (instant access-token revocation).
   */
  epoch: number;
}

const KID = "primary";
const ALG = "HS256";

/**
 * Access-token signer/verifier. HS256 + JWT_SECRET (≥32B). Adds a `kid`
 * header so future rotations can roll without breaking outstanding tokens.
 *
 * Access tokens are short-lived (default 15m, env ACCESS_TOKEN_TTL). They
 * are NOT revocable server-side in v1 — operator accepts the trade-off; a
 * "session epoch" feature is deferred to Phase 03 (REQ-AUTH-004).
 */
@Injectable()
export class JwtService implements OnModuleInit {
  private readonly logger = new Logger(JwtService.name);
  private secret!: Uint8Array;
  private accessTtlSec!: number;

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const raw = this.config.get<string>("JWT_SECRET") ?? process.env.JWT_SECRET;
    if (!raw) throw new Error("JWT_SECRET is not set");
    // Accept base64 (preferred), hex, or raw utf8 — pick longest >= 32B.
    const candidates: Buffer[] = [];
    try {
      const b = Buffer.from(raw, "base64");
      if (b.length >= 32 && Buffer.from(b.toString("base64").replace(/=+$/, ""), "base64").equals(b)) {
        candidates.push(b);
      }
    } catch {
      /* ignore */
    }
    if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
      const b = Buffer.from(raw, "hex");
      if (b.length >= 32) candidates.push(b);
    }
    const u = Buffer.from(raw, "utf8");
    if (u.length >= 32) candidates.push(u);
    if (candidates.length === 0) {
      throw new Error("JWT_SECRET must decode to >= 32 bytes (base64/hex/utf8)");
    }
    const buf = candidates.reduce((a, b) => (b.length > a.length ? b : a));
    this.secret = new Uint8Array(buf);

    const ttlRaw = this.config.get<string>("ACCESS_TOKEN_TTL") ?? process.env.ACCESS_TOKEN_TTL;
    const n = ttlRaw ? Number.parseInt(ttlRaw, 10) : NaN;
    this.accessTtlSec = Number.isFinite(n) && n > 0 ? n : 900;
    this.logger.log(`JwtService ready (kid=${KID}, ttl=${this.accessTtlSec.toString()}s)`);
  }

  accessTtlSeconds(): number {
    return this.accessTtlSec;
  }

  /**
   * Package-private accessor — exposes the symmetric secret to sibling
   * services that sign tokens with the SAME key but different shape (e.g.
   * `StepUpJwtService` for the 2FA step-up token). Phase 03 introduces
   * step-up tokens that carry `purpose:"2fa-stepup"` and must not be
   * accepted by `JwtAuthGuard` (which now rejects any token with a
   * `purpose` claim — see jwt-auth.guard.ts). Sharing the secret keeps the
   * secret-rotation surface to one variable; safety is enforced by the
   * `purpose` discriminator.
   */
  exposeSecret(): Uint8Array {
    return this.secret;
  }

  async signAccessToken(claims: AccessTokenClaims): Promise<string> {
    return await new SignJWT({ sid: claims.sid, fam: claims.fam, epoch: claims.epoch })
      .setProtectedHeader({ alg: ALG, kid: KID })
      .setSubject(claims.sub)
      .setIssuedAt()
      .setExpirationTime(`${this.accessTtlSec.toString()}s`)
      .sign(this.secret);
  }

  async verifyAccessToken(token: string): Promise<AccessTokenClaims & { iat: number; exp: number }> {
    const { payload } = await jwtVerify(token, this.secret, { algorithms: [ALG] });
    if (typeof payload.sub !== "string" || typeof payload.sid !== "string" || typeof payload.fam !== "string") {
      throw new Error("malformed access token claims");
    }
    if (typeof payload.epoch !== "number" || !Number.isInteger(payload.epoch) || payload.epoch < 0) {
      throw new Error("malformed access token claims (epoch)");
    }
    return {
      sub: payload.sub,
      sid: payload.sid,
      fam: payload.fam,
      epoch: payload.epoch,
      iat: payload.iat ?? 0,
      exp: payload.exp ?? 0,
    };
  }
}
