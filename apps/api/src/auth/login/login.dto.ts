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
    email: z.string().email().toLowerCase().trim(),
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
