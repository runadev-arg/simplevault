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
export const MeResponseSchema = z
  .object({
    id: z.string().uuid(),
    email: z.string().email(),
    createdAt: z.string().datetime(),
    argon2Params: z.object({
      memoryKiB: z.number().int().positive(),
      iterations: z.number().int().positive(),
      parallelism: z.literal(1),
    }),
  })
  .strict();
export type MeResponse = z.infer<typeof MeResponseSchema>;
