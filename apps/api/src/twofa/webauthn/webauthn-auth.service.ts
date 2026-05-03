import {
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
} from "@nestjs/common";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import {
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/types";
import { and, eq, sql } from "drizzle-orm";

import { JwtService } from "../../auth/jwt/jwt.service.js";
import {
  SessionService,
  type IssuedRefreshToken,
} from "../../auth/sessions/session.service.js";
import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { DbService } from "../../db/db.service.js";

import { WebauthnRegisterService } from "./webauthn-register.service.js";

const CHALLENGE_TTL_MS = 120 * 1000;

export interface WebauthnFinishAuthResult {
  accessToken: string;
  refresh: IssuedRefreshToken;
  /** Plain wrapped key material to return in the body, mirroring /auth/login. */
  bodyExtras: {
    expiresIn: number;
    wrappedMasterDek: string;
    wrappedMasterDekRecovery: string;
    argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 };
    serverArgonSalt: string;
    userArgonSalt: string;
    userPubKey: string;
    wrappedUserSigningSk: string;
    wrappedUserKxSk: string;
  };
}

/**
 * WebAuthn authentication ceremony.
 *
 * Truth 3+4 (03-INDEX): begin emits the assertion options bound to a
 * fresh challenge; finish atomically consumes via DELETE … RETURNING
 * (Key Link 2), runs the cryptographic verify with `expectedRPID` and
 * `expectedOrigin` passed explicitly (Key Link 9), enforces the counter-
 * regression rule (`stored>0 && new<=stored` → reject + audit
 * `counter_regression`), and on success bumps `counter` + `last_used_at`
 * and mints a full session via the existing Phase-02 `SessionService`
 * primitive.
 */
@Injectable()
export class WebauthnAuthService {
  private readonly logger = new Logger(WebauthnAuthService.name);

  constructor(
    private readonly db: DbService,
    private readonly registerSvc: WebauthnRegisterService,
    private readonly jwt: JwtService,
    private readonly sessions: SessionService,
  ) {}

  /**
   * Emit `PublicKeyCredentialRequestOptionsJSON` + persist the challenge.
   * Caller MUST already have validated a step-up token (controller-level
   * guard).
   */
  async beginAuth(userId: string): Promise<PublicKeyCredentialRequestOptionsJSON> {
    const creds = await this.db.db
      .select({
        credentialId: schema.webauthnCredentials.credentialId,
        transports: schema.webauthnCredentials.transports,
      })
      .from(schema.webauthnCredentials)
      .where(eq(schema.webauthnCredentials.userId, userId));

    if (creds.length === 0) {
      throw new HttpException(
        {
          error: {
            code: ErrorCodes.AUTH_2FA_NO_METHOD,
            message: "No WebAuthn credential enrolled",
          },
        },
        HttpStatus.BAD_REQUEST,
      );
    }

    const opts = await generateAuthenticationOptions({
      rpID: this.registerSvc.rpID(),
      userVerification: "required",
      allowCredentials: creds.map((c) => {
        const t = c.transports;
        const out: { id: string; transports?: AuthenticatorTransportFuture[] } = {
          id: Buffer.from(c.credentialId).toString("base64url"),
        };
        if (Array.isArray(t) && t.length > 0) {
          out.transports = t as AuthenticatorTransportFuture[];
        }
        return out;
      }),
      timeout: 60_000,
    });

    const challengeBytes = Buffer.from(opts.challenge, "base64url");
    const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);

    await this.db.db
      .insert(schema.webauthnChallenges)
      .values({
        userId,
        kind: "auth",
        challenge: challengeBytes,
        expiresAt,
      })
      .onConflictDoUpdate({
        target: [schema.webauthnChallenges.userId, schema.webauthnChallenges.kind],
        set: {
          challenge: challengeBytes,
          expiresAt,
          createdAt: new Date(),
        },
      });

    return opts;
  }

  /**
   * Atomically consume the auth challenge, verify the assertion, enforce
   * counter regression, then mint a fresh session.
   */
  async finishAuth(
    userId: string,
    body: AuthenticationResponseJSON,
    ip: string,
    ua: string | undefined,
  ): Promise<WebauthnFinishAuthResult> {
    const consumed = await this.db.db.execute<{ challenge: Buffer; expires_at: Date }>(sql`
      DELETE FROM ${schema.webauthnChallenges}
      WHERE user_id = ${userId} AND kind = 'auth'
      RETURNING challenge, expires_at
    `);
    const ch = consumed.rows[0];
    if (!ch) {
      this.failAudit(userId, "challenge_invalid");
      throw this.invalidChallenge();
    }
    const expiresAt = new Date(ch.expires_at);
    if (expiresAt.getTime() <= Date.now()) {
      this.failAudit(userId, "challenge_expired");
      throw this.invalidChallenge();
    }

    // Locate the credential the assertion claims; `body.id` is base64url-
    // encoded credential ID per WebAuthn JSON envelope.
    let credIdBytes: Buffer;
    try {
      credIdBytes = Buffer.from(body.id, "base64url");
    } catch {
      this.failAudit(userId, "bad_credential_id");
      throw this.verificationFailed();
    }
    const credRows = await this.db.db
      .select()
      .from(schema.webauthnCredentials)
      .where(
        and(
          eq(schema.webauthnCredentials.userId, userId),
          eq(schema.webauthnCredentials.credentialId, credIdBytes),
        ),
      )
      .limit(1);
    const cred = credRows[0];
    if (!cred) {
      this.failAudit(userId, "credential_not_found");
      throw this.verificationFailed();
    }

    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: body,
        expectedChallenge: Buffer.from(ch.challenge).toString("base64url"),
        expectedOrigin: this.registerSvc.webauthnOrigin(),
        expectedRPID: this.registerSvc.rpID(),
        credential: {
          id: Buffer.from(cred.credentialId).toString("base64url"),
          publicKey: Buffer.from(cred.publicKey),
          counter: cred.counter,
          transports: cred.transports as AuthenticatorTransportFuture[],
        },
        requireUserVerification: true,
      });
    } catch (err) {
      this.failAudit(userId, "verification_threw");
      this.logger.debug(
        { err: err instanceof Error ? err.message : String(err) },
        "auth.verify.throw",
      );
      throw this.verificationFailed();
    }

    if (!verification.verified) {
      this.failAudit(userId, "verification_failed");
      throw this.verificationFailed();
    }

    // Counter regression check (Key Link 4 + Truth 4): only enforced when
    // the stored counter has ever advanced. Some authenticators (e.g.
    // resident-key passkeys synced via iCloud Keychain) never increment
    // and stay at 0 forever; rejecting `new <= 0` would lock them out.
    const newCounter = verification.authenticationInfo.newCounter;
    if (cred.counter > 0 && newCounter <= cred.counter) {
      this.failAudit(userId, "counter_regression");
      throw this.verificationFailed();
    }

    await this.db.db
      .update(schema.webauthnCredentials)
      .set({ counter: newCounter, lastUsedAt: new Date() })
      .where(eq(schema.webauthnCredentials.id, cred.id));

    // Mint full session — re-uses the Phase-02 SessionService primitive.
    const refresh = await this.sessions.createOnLogin(userId, ip, ua);
    // Plan 04 hand-off: read the user's current session_epoch.
    // SessionService.getEpoch was added by Plan 04; falls back to 0 if
    // unavailable in older builds.
    const epoch = await this.readEpoch(userId);
    const accessToken = await this.jwt.signAccessToken({
      sub: userId,
      sid: refresh.sessionId,
      fam: refresh.familyId,
      epoch,
    });

    // Pull wrapped material to mirror Phase-02 /auth/login envelope shape.
    const userRows = await this.db.db
      .select({
        argon2_params: schema.users.argon2Params,
        server_argon_salt: schema.users.serverArgonSalt,
        user_argon_salt: schema.users.userArgonSalt,
        wrapped_master_dek: schema.users.wrappedMasterDek,
        wrapped_master_dek_recovery: schema.users.wrappedMasterDekRecovery,
        user_pub_key: schema.users.userPubKey,
        wrapped_user_signing_sk: schema.users.wrappedUserSigningSk,
        wrapped_user_kx_sk: schema.users.wrappedUserKxSk,
      })
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .limit(1);
    const u = userRows[0];
    if (!u) {
      // Should be impossible at this point — the credential FK guarantees
      // the user exists. Fail closed.
      throw this.verificationFailed();
    }

    AuditEventService.emit(this.logger, {
      action: AuditAction.TwoFaWebauthnAuthOk,
      actorUserId: userId,
      targetId: cred.id,
      outcome: "ok",
      ipHashB64: this.sessions.hashIp(ip).toString("base64"),
      uaFamily: this.sessions.parseUaFamily(ua),
      data: { familyId: refresh.familyId },
    });

    return {
      accessToken,
      refresh,
      bodyExtras: {
        expiresIn: this.jwt.accessTtlSeconds(),
        wrappedMasterDek: Buffer.from(u.wrapped_master_dek).toString("base64"),
        wrappedMasterDekRecovery: Buffer.from(u.wrapped_master_dek_recovery).toString("base64"),
        argon2Params: u.argon2_params,
        serverArgonSalt: Buffer.from(u.server_argon_salt).toString("base64"),
        userArgonSalt: Buffer.from(u.user_argon_salt).toString("base64"),
        userPubKey: Buffer.from(u.user_pub_key).toString("base64"),
        wrappedUserSigningSk: Buffer.from(u.wrapped_user_signing_sk).toString("base64"),
        wrappedUserKxSk: Buffer.from(u.wrapped_user_kx_sk).toString("base64"),
      },
    };
  }

  // -------- internal helpers --------

  /**
   * Read `users.session_epoch`. Plan 04 wires `SessionService.getEpoch` for
   * a Redis-cached fast-path; we go through it via reflection so this
   * service compiles whether or not getEpoch has shipped yet.
   */
  private async readEpoch(userId: string): Promise<number> {
    const svc = this.sessions as unknown as { getEpoch?: (uid: string) => Promise<number> };
    if (typeof svc.getEpoch === "function") {
      return await svc.getEpoch(userId);
    }
    const rows = await this.db.db
      .select({ epoch: schema.users.sessionEpoch })
      .from(schema.users)
      .where(eq(schema.users.id, userId))
      .limit(1);
    return rows[0]?.epoch ?? 0;
  }

  private invalidChallenge(): HttpException {
    return new HttpException(
      {
        error: {
          code: ErrorCodes.WEBAUTHN_CHALLENGE_INVALID,
          message: "Webauthn challenge invalid or expired",
        },
      },
      HttpStatus.BAD_REQUEST,
    );
  }

  private verificationFailed(): HttpException {
    return new HttpException(
      {
        error: {
          code: ErrorCodes.WEBAUTHN_VERIFICATION_FAILED,
          message: "Webauthn verification failed",
        },
      },
      HttpStatus.UNAUTHORIZED,
    );
  }

  private failAudit(userId: string, reason: string): void {
    AuditEventService.emit(this.logger, {
      action: AuditAction.TwoFaWebauthnAuthFail,
      actorUserId: userId,
      targetId: null,
      outcome: "fail",
      reason,
    });
  }
}
