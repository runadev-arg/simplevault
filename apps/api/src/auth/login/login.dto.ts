import { z } from "zod";

const b64 = (raw: string): Buffer => Buffer.from(raw, "base64");

const fixedB64 = (n: number) =>
  z
    .string()
    .min(1)
    .transform((v, ctx) => {
      const buf = b64(v);
      if (buf.length !== n) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `expected ${n.toString()} bytes after base64 decode, got ${buf.length.toString()}`,
        });
        return z.NEVER;
      }
      return buf;
    });

export const LoginSchema = z
  .object({
    // RFC 5321 ceiling — also bounds throttler login-email Redis key length (FINDING-0017 + 0022 fold).
    email: z.string().email().toLowerCase().trim().max(254),
    /** 32-byte verifier candidate the client computed via Argon2id(secret_key, server_argon_salt, argon2_params). */
    argon2SecretKeyHash: fixedB64(32),
  })
  .strict();

export type LoginDto = z.infer<typeof LoginSchema>;

export interface LoginResponseBody {
  accessToken: string;
  expiresIn: number;
  /** Wrapped key material the client needs to decrypt locally. base64-encoded bytea blobs. */
  wrappedMasterDek: string;
  wrappedMasterDekRecovery: string;
  argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 };
  serverArgonSalt: string;
  userArgonSalt: string;
  userPubKey: string;
  wrappedUserSigningSk: string;
  wrappedUserKxSk: string;
}

/**
 * Phase 03 Plan 08 — `/auth/login` 2FA-required branch (Truth 8).
 *
 * When the verified user has ≥1 active 2FA method (webauthn_credentials +
 * totp_credentials count ≥ 1), `/auth/login` does NOT mint a full session.
 * Instead it returns this body shape — distinct from `LoginResponseBody` —
 * carrying a step-up JWT (`{sub, purpose:"2fa-stepup", epoch}`, exp = iat +
 * STEP_UP_TOKEN_TTL) that authorises ONLY `/2fa/*` endpoints.
 *
 * NO `__Host-refresh` cookie is set on this branch (the user has no refresh
 * family yet — the family is created by `/2fa/webauthn/finish-auth` or
 * `/2fa/totp/verify` once the 2FA ceremony completes).
 *
 * `kind: "2fa-required"` is the discriminator the web client uses to branch.
 * The 1FA-only branch (`LoginResponseBody`) intentionally does NOT carry a
 * `kind` field — keeps Phase-02 byte-equal regression-free for callers that
 * pre-date this plan.
 */
export interface LoginStepUpResponseBody {
  kind: "2fa-required";
  stepUpToken: string;
  twoFa: {
    webauthnAvailable: boolean;
    totpAvailable: boolean;
  };
}
