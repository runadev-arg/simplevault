import { z } from "zod";

export const HealthResponseSchema = z.object({
  status: z.enum(["ok", "degraded", "down"]),
  db: z.enum(["ok", "down"]),
  redis: z.enum(["ok", "down"]),
  timestamp: z.string().datetime(),
});

export type HealthResponse = z.infer<typeof HealthResponseSchema>;

/**
 * `GET /me` strict-allow-list response.
 *
 * LOAD-BEARING: this is the only output schema for /me. Phase 02-11 (web)
 * consumes it; Phase 03+ (sessions, settings) MAY add fields but only via
 * an explicit `.extend(...)` here — never by ad-hoc additions in the API
 * controller. The server-side serialiser MUST `.parse(...)` against this
 * schema as a defence-in-depth check before responding (so a future ORM
 * hydration leak surfaces as a 500, not a silent data exfil).
 *
 * Explicitly NOT in the v1 shape (per 02-09 plan):
 *  - `argon2_secret_key_hash` (the verifier — never leaked, even to owner)
 *  - `wrapped_master_dek*` / `wrapped_user_*` / `user_pub_key`
 *    (returned in the 200 login response, not /me; SPA caches them in memory
 *    after login. /me is for "who am I" — not key-material refetch.)
 *  - `recovery_hmac` / `wrapped_master_dek_recovery` (recovery flow only)
 *  - any session metadata (Phase 03 owns sessions UI).
 */
/**
 * Phase 03 Plan 03 — TOTP enrolment + verification request schemas.
 *
 * SECURITY (Key Link 3 — TOTP secret is BROWSER-ONLY):
 * - `wrappedSecret` is the AEAD-wrapped 20-byte TOTP secret (XChaCha20-
 *   Poly1305 with key=master_DEK, AAD label "sv:user-totp:v1|" +
 *   sha256(lower(email))). The server NEVER decrypts it.
 * - `candidateStep` is the RFC 6238 step the client computed locally
 *   AFTER unwrapping the secret in-browser. The server only does an
 *   atomic CAS replay-guard UPDATE — it never runs HMAC-SHA-1.
 *
 * `issuanceNonce` (begin-register output, finish-register input) is a
 * 32-byte random base64url string the server signs into a Redis
 * single-use cache so finish-register can prove the begin-register
 * preceded it.
 */
const boundedB64 = (min: number, max: number) =>
  z
    .string()
    .min(1)
    .transform((v, ctx) => {
      const buf = Buffer.from(v, "base64");
      if (buf.length < min || buf.length > max) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `expected ${min.toString()}..${max.toString()} bytes after base64 decode, got ${buf.length.toString()}`,
        });
        return z.NEVER;
      }
      return buf;
    });

/** Output of POST /2fa/totp/begin-register. */
export const TotpBeginRegisterResponseSchema = z
  .object({
    /** 32-byte random, base64url. Single-use, TTL 120s, bound to user_id. */
    issuanceNonce: z.string().min(1).max(128),
  })
  .strict();
export type TotpBeginRegisterResponse = z.infer<typeof TotpBeginRegisterResponseSchema>;

/** Input of POST /2fa/totp/finish-register. */
export const TotpFinishRegisterSchema = z
  .object({
    issuanceNonce: z.string().min(1).max(128),
    // 20-byte TOTP secret + 16-byte Poly1305 tag = 36 bytes; allow up to 64
    // to leave headroom for any future scheme bump that lands in the same wrap.
    wrappedSecret: boundedB64(36, 128),
    // AAD bytes used at wrap time. Per Phase 02 + CRYPTO-STACK §3:
    // "sv:user-totp:v1|" (16 bytes) + sha256(lower(email)) (32 bytes) = 48 bytes,
    // plus a 24-byte random nonce stored alongside the ciphertext = 72 bytes total.
    // Bound generously to 16..256.
    encryptedSecretAad: boundedB64(16, 256),
    name: z.string().trim().min(1).max(64),
    /** Step the client verified locally to prove it knows the plaintext. */
    candidateStep: z.number().int().nonnegative(),
  })
  .strict();
export type TotpFinishRegisterDto = z.infer<typeof TotpFinishRegisterSchema>;

/** Output of POST /2fa/totp/finish-register. */
export const TotpFinishRegisterResponseSchema = z
  .object({
    id: z.string().uuid(),
    name: z.string(),
  })
  .strict();
export type TotpFinishRegisterResponse = z.infer<typeof TotpFinishRegisterResponseSchema>;

/** Input of POST /2fa/totp/verify (called by step-up-token holders). */
export const TotpVerifySchema = z
  .object({
    credentialId: z.string().uuid(),
    candidateStep: z.number().int().nonnegative(),
  })
  .strict();
export type TotpVerifyDto = z.infer<typeof TotpVerifySchema>;

export const MeResponseSchema = z
  .object({
    id: z.string().uuid(),
    // RFC 5321 ceiling — mirrors users.email varchar(254) (FINDING-0017 fold).
    email: z.string().email().max(254),
    createdAt: z.string().datetime(),
    argon2Params: z.object({
      memoryKiB: z.number().int().positive(),
      iterations: z.number().int().positive(),
      parallelism: z.literal(1),
    }),
  })
  .strict();
export type MeResponse = z.infer<typeof MeResponseSchema>;
