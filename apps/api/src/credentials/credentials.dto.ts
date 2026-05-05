import { z } from "zod";

import {
  AAD_PARAMS_JSON_MAX_BYTES,
  CIPHERTEXT_MAX_BYTES,
} from "./credentials.constants.js";

/**
 * Phase 04 / Plan 02 — credentials request DTOs (`.strict()` Zod).
 *
 * Bytea handling: bodies arrive as JSON with base64-encoded `ciphertext` +
 * `nonce`. The DTO transform decodes them into `Uint8Array` after validating
 * the post-decode length. Field caps duplicate the body-parser cap from
 * Plan 04-03 (defence-in-depth — the body-parser fires first; these field
 * caps catch bypasses).
 *
 * `.strict()` (Truth 18 system-wide) rejects unknown keys outright — a
 * forward-compat client adding a new field surfaces as a 400 instead of a
 * silent strip, which prevents request smuggling on schema mismatch.
 */

const NONCE_BYTES = 24;

/** Base64 → bounded Uint8Array. Mirrors the boundedB64 helper in Phase-03. */
const base64ToBytesBounded = (
  min: number,
  max: number,
  label: string,
): z.ZodType<Uint8Array, z.ZodTypeDef, unknown> =>
  z
    .string()
    .min(1)
    .transform((v, ctx) => {
      // Accept both base64 + base64url (sibling Plan 04-04 emits base64url
      // for AAD parity); `Buffer.from(v, "base64")` is permissive enough
      // for both since URL-safe alphabet is a strict subset.
      const buf = Buffer.from(v, "base64");
      if (buf.length < min || buf.length > max) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${label}: expected ${min.toString()}..${max.toString()} bytes after base64 decode, got ${buf.length.toString()}`,
        });
        return z.NEVER;
      }
      return new Uint8Array(buf);
    });

/**
 * `POST /credentials` — Plan 04-10 cross-dep: client supplies the
 * `credentialId` so the AAD it just encrypted is self-consistent on POST
 * (avoids a two-roundtrip "encrypt with placeholder, server returns id,
 * re-encrypt" dance). Server uses `COALESCE($credentialId, gen_random_uuid())`.
 */
export const CredentialCreateSchema = z
  .object({
    vaultId: z.string().uuid(),
    credentialId: z.string().uuid().optional(),
    ciphertext: base64ToBytesBounded(1, CIPHERTEXT_MAX_BYTES, "ciphertext"),
    nonce: base64ToBytesBounded(NONCE_BYTES, NONCE_BYTES, "nonce"),
    aadParamsJson: z.string().min(1).max(AAD_PARAMS_JSON_MAX_BYTES),
    version: z.literal(1),
  })
  .strict();
export type CredentialCreateDto = z.infer<typeof CredentialCreateSchema>;

/**
 * `PATCH /credentials/:id` — `version` is the CAS-witness (caller's
 * known-current value). Server CAS bumps the row to `version + 1` (Key
 * Link 2 of 04-INDEX). Stale witness → 409 `CREDENTIAL_VERSION_CONFLICT`.
 */
export const CredentialUpdateSchema = z
  .object({
    ciphertext: base64ToBytesBounded(1, CIPHERTEXT_MAX_BYTES, "ciphertext"),
    nonce: base64ToBytesBounded(NONCE_BYTES, NONCE_BYTES, "nonce"),
    aadParamsJson: z.string().min(1).max(AAD_PARAMS_JSON_MAX_BYTES),
    version: z.number().int().nonnegative(),
  })
  .strict();
export type CredentialUpdateDto = z.infer<typeof CredentialUpdateSchema>;
