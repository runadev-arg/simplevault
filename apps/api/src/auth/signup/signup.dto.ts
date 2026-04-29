import { z } from "zod";

/**
 * Signup body — strictly an envelope of client-computed crypto artifacts.
 *
 * SECURITY INVARIANT (REQ-CRYPTO-003): the server NEVER receives the master
 * password, the secret_key (raw), the recovery phrase, or any KEK/DEK. The
 * `.strict()` here makes that a hard contract — payloads carrying any
 * unexpected key (`password`, `secret_key`, `recoveryPhrase`, …) fail with
 * a 400 BEFORE any handler runs. Pino redaction is defence in depth.
 *
 * Every bytea field is base64 on the wire and decodes to a `Buffer` with a
 * size check. The fixed-length checks (32B verifier, 32B userPubKey, etc.)
 * defend the API boundary against malformed clients and fuzzing.
 */

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

const variableB64 = (min: number, max: number) =>
  z
    .string()
    .min(1)
    .transform((v, ctx) => {
      const buf = b64(v);
      if (buf.length < min || buf.length > max) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `expected ${min.toString()}..${max.toString()} bytes after base64 decode, got ${buf.length.toString()}`,
        });
        return z.NEVER;
      }
      return buf;
    });

export const SignupSchema = z
  .object({
    inviteId: z.string().uuid(),
    argon2SecretKeyHash: fixedB64(32),
    argon2Params: z
      .object({
        memoryKiB: z.number().int().positive().max(1024 * 1024),
        iterations: z.number().int().positive().max(64),
        parallelism: z.literal(1),
      })
      .strict(),
    userArgonSalt: fixedB64(16),
    // AEAD blob (XChaCha20-Poly1305): 24B nonce + ciphertext (32B DEK + 16B tag) = 72B.
    // Allow some slack to absorb canonical-blob layout (e.g. an AAD-version prefix byte).
    wrappedMasterDek: variableB64(32, 256),
    wrappedMasterDekRecovery: variableB64(32, 256),
    recoveryInnerHash: fixedB64(32),
    userPubKey: fixedB64(32),
    wrappedUserSigningSk: variableB64(32, 256),
    wrappedUserKxSk: variableB64(32, 256),
  })
  .strict();

export type SignupDto = z.infer<typeof SignupSchema>;

export interface SignupResponse {
  userId: string;
  email: string;
  createdAt: string;
}
