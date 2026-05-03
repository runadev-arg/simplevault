import {
  HttpException,
  HttpStatus,
  Injectable,
  Logger,
  type OnModuleInit,
} from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { schema } from "@simplevault/db";
import { ErrorCodes } from "@simplevault/shared/errors";
import { and, eq, sql } from "drizzle-orm";
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type {
  AuthenticatorTransportFuture,
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";

import { AuditAction, AuditEventService } from "../../common/audit-events.js";
import { DbService } from "../../db/db.service.js";

const CHALLENGE_TTL_MS = 120 * 1000;

/**
 * WebAuthn registration ceremony.
 *
 * Truth 1+2 (03-INDEX): begin emits 32-byte challenge bound to the user via a
 * row in `webauthn_challenges` (kind='register'). Finish atomically consumes
 * via `DELETE … RETURNING`, verifies the attestation against the consumed
 * challenge with `expectedRPID` and `expectedOrigin` passed explicitly (Key
 * Link 9), and inserts the credential row.
 *
 * Operator decisions baked in:
 *   - RP ID = WEBAUTHN_RP_ID (apex pass.runadev.com in prod) — fail-fast
 *     at boot if NODE_ENV=production AND WEBAUTHN_RP_ID is unset.
 *   - userVerification = required.
 *   - attestation = none.
 *   - pubKeyCredParams = [-7, -257] (ES256 + RS256).
 */
@Injectable()
export class WebauthnRegisterService implements OnModuleInit {
  private readonly logger = new Logger(WebauthnRegisterService.name);
  private rpId!: string;
  private rpName!: string;
  private origin!: string;

  constructor(
    private readonly db: DbService,
    private readonly config: ConfigService,
  ) {}

  onModuleInit(): void {
    const nodeEnv = this.config.get<string>("NODE_ENV") ?? process.env.NODE_ENV ?? "development";
    const rpId = this.config.get<string>("WEBAUTHN_RP_ID") ?? process.env.WEBAUTHN_RP_ID ?? "";
    const rpName =
      this.config.get<string>("WEBAUTHN_RP_NAME") ?? process.env.WEBAUTHN_RP_NAME ?? "SimpleVault";
    const origin =
      this.config.get<string>("WEBAUTHN_ORIGIN") ?? process.env.WEBAUTHN_ORIGIN ?? "";

    if (nodeEnv === "production") {
      if (!rpId) throw new Error("WEBAUTHN_RP_ID must be set in production");
      if (!origin) throw new Error("WEBAUTHN_ORIGIN must be set in production");
    }
    // Dev fallbacks — match docker-compose defaults.
    this.rpId = rpId || "localhost";
    this.rpName = rpName;
    this.origin = origin || "http://localhost:3000";
    this.logger.log(`Webauthn config: rpId=${this.rpId}, origin=${this.origin}`);
  }

  rpID(): string {
    return this.rpId;
  }

  webauthnOrigin(): string {
    return this.origin;
  }

  /**
   * Begin a registration ceremony. Returns the
   * `PublicKeyCredentialCreationOptionsJSON` the browser passes to
   * `navigator.credentials.create({publicKey: ...})`.
   *
   * The unique `(user_id, kind)` index on `webauthn_challenges` enforces
   * "one in-flight register per user"; calling begin twice in a row
   * UPSERTs (replaces) the prior row.
   */
  async beginRegister(
    userId: string,
    userEmail: string,
  ): Promise<PublicKeyCredentialCreationOptionsJSON> {
    const existing = await this.db.db
      .select({
        credentialId: schema.webauthnCredentials.credentialId,
        transports: schema.webauthnCredentials.transports,
      })
      .from(schema.webauthnCredentials)
      .where(eq(schema.webauthnCredentials.userId, userId));

    const opts = await generateRegistrationOptions({
      rpName: this.rpName,
      rpID: this.rpId,
      userID: new TextEncoder().encode(userId),
      userName: userEmail,
      userDisplayName: userEmail,
      attestationType: "none",
      authenticatorSelection: {
        userVerification: "required",
        residentKey: "preferred",
      },
      supportedAlgorithmIDs: [-7, -257],
      excludeCredentials: existing.map((c) => {
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
        kind: "register",
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
   * Atomically consume the in-flight register challenge, verify the
   * attestation, and insert a `webauthn_credentials` row.
   *
   * SECURITY (Key Link 2): the consume MUST be a single statement
   * `DELETE … RETURNING` — never SELECT-then-DELETE in two roundtrips.
   *
   * SECURITY (Key Link 9): `expectedRPID` and `expectedOrigin` MUST be
   * passed explicitly to `verifyRegistrationResponse` — defaults are
   * not safe.
   */
  async finishRegister(
    userId: string,
    body: RegistrationResponseJSON,
    name: string,
  ): Promise<{ id: string; name: string }> {
    // Atomic consume.
    const consumed = await this.db.db.execute<{ challenge: Buffer; expires_at: Date }>(sql`
      DELETE FROM ${schema.webauthnChallenges}
      WHERE user_id = ${userId} AND kind = 'register'
      RETURNING challenge, expires_at
    `);
    const row = consumed.rows[0];
    if (!row) {
      this.failAudit(userId, "challenge_invalid");
      throw this.invalidChallenge();
    }
    const expiresAt = new Date(row.expires_at);
    if (expiresAt.getTime() <= Date.now()) {
      this.failAudit(userId, "challenge_expired");
      throw this.invalidChallenge();
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: body,
        expectedChallenge: Buffer.from(row.challenge).toString("base64url"),
        expectedOrigin: this.origin,
        expectedRPID: this.rpId,
        requireUserVerification: true,
      });
    } catch (err) {
      this.failAudit(userId, "verification_threw");
      this.logger.debug({ err: err instanceof Error ? err.message : String(err) }, "register.verify.throw");
      throw this.verificationFailed();
    }

    if (!verification.verified || !verification.registrationInfo) {
      this.failAudit(userId, "verification_failed");
      throw this.verificationFailed();
    }
    const ri = verification.registrationInfo;

    // v11 shape: registrationInfo.credential.{id,publicKey,counter,transports?}
    const credentialIdBuf = Buffer.from(ri.credential.id, "base64url");
    const publicKeyBuf = Buffer.from(ri.credential.publicKey);
    const aaguidBuf = ri.aaguid ? Buffer.from(ri.aaguid, "hex") : null;
    const transports = (body.response.transports ?? ri.credential.transports ?? []) as string[];

    const inserted = await this.db.db
      .insert(schema.webauthnCredentials)
      .values({
        userId,
        credentialId: credentialIdBuf,
        publicKey: publicKeyBuf,
        counter: ri.credential.counter,
        transports,
        aaguid: aaguidBuf,
        name,
      })
      .returning({
        id: schema.webauthnCredentials.id,
        name: schema.webauthnCredentials.name,
      });
    const out = inserted[0];
    if (!out) throw this.verificationFailed();

    AuditEventService.emit(this.logger, {
      action: AuditAction.TwoFaWebauthnRegisterOk,
      actorUserId: userId,
      targetId: out.id,
      outcome: "ok",
    });
    return out;
  }

  // ---- internal helpers ----

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
      action: AuditAction.TwoFaWebauthnRegisterFail,
      actorUserId: userId,
      targetId: null,
      outcome: "fail",
      reason,
    });
  }
}

// Suppress unused `and` import — kept for future composite where-clauses.
void and;
