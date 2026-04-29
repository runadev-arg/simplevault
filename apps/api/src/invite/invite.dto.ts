import { z } from "zod";

/**
 * `POST /invite/redeem` request body.
 *
 * The `code` is the canonical Crockford-base32 hyphenated string the CLI
 * (Plan 02-06) printed to stdout — typically `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX`
 * (16 random bytes -> 26 chars, hyphenated every 4 -> 31 chars). We accept
 * a generous superset (allow hyphens optionally, allow all base32 chars +
 * digits; case-insensitive) but never log the raw code.
 *
 * `.strict()` rejects unknown keys — defence in depth atop Pino redaction.
 */
export const InviteRedeemSchema = z
  .object({
    code: z
      .string()
      .min(8, "code too short")
      .max(64, "code too long")
      // base32 alphabet (Crockford excludes I/L/O/U) + hyphens; case-insensitive.
      .regex(/^[0-9A-HJKMNP-TV-Za-hjkmnp-tv-z-]+$/, "invalid code format"),
  })
  .strict();

export type InviteRedeemDto = z.infer<typeof InviteRedeemSchema>;

export interface InviteRedeemResponse {
  inviteId: string;
  email: string;
  argon2Params: { memoryKiB: number; iterations: number; parallelism: 1 };
  serverArgonSalt: string; // base64
}
