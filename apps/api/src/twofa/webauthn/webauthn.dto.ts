import { z } from "zod";

/**
 * Phase 03-02 — WebAuthn DTOs.
 *
 * The shape of the registration / authentication response objects
 * matches `@simplewebauthn/server` v11's
 * `RegistrationResponseJSON` / `AuthenticationResponseJSON`. We DON'T
 * re-derive the entire (deeply-nested) schema with Zod — instead we
 * Zod-validate the trivially-typed fields (top-level shape, strings,
 * lengths) and let `verifyRegistrationResponse` /
 * `verifyAuthenticationResponse` do the deep crypto-aware validation.
 *
 * Rationale: the underlying CBOR-decoded structure of an authenticator
 * response is enormous and library-private; mirroring it as Zod would
 * cause every minor library upgrade to break us. Library version is
 * pinned (^11.0.0) so we trust its parser.
 */

/** Minimal top-level shape of `RegistrationResponseJSON`. */
const registrationResponseShape = z
  .object({
    id: z.string().min(1).max(2048),
    rawId: z.string().min(1).max(2048),
    type: z.literal("public-key"),
    response: z
      .object({
        clientDataJSON: z.string().min(1).max(8192),
        attestationObject: z.string().min(1).max(32768),
        // Optional fields varied by authenticator; `passthrough` so the
        // `@simplewebauthn` library can read them.
        transports: z.array(z.string().max(32)).max(8).optional(),
        publicKeyAlgorithm: z.number().int().optional(),
        publicKey: z.string().optional(),
        authenticatorData: z.string().optional(),
      })
      .passthrough(),
    clientExtensionResults: z.record(z.unknown()).default({}),
    authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
  })
  .passthrough();

export const FinishRegisterSchema = z
  .object({
    response: registrationResponseShape,
    name: z.string().min(1).max(64),
  })
  .strict();
export type FinishRegisterDto = z.infer<typeof FinishRegisterSchema>;

/** Minimal top-level shape of `AuthenticationResponseJSON`. */
const authenticationResponseShape = z
  .object({
    id: z.string().min(1).max(2048),
    rawId: z.string().min(1).max(2048),
    type: z.literal("public-key"),
    response: z
      .object({
        clientDataJSON: z.string().min(1).max(8192),
        authenticatorData: z.string().min(1).max(8192),
        signature: z.string().min(1).max(2048),
        userHandle: z.string().max(2048).optional(),
      })
      .passthrough(),
    clientExtensionResults: z.record(z.unknown()).default({}),
    authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
  })
  .passthrough();

export const FinishAuthSchema = z
  .object({
    response: authenticationResponseShape,
  })
  .strict();
export type FinishAuthDto = z.infer<typeof FinishAuthSchema>;
