import {
  TwoFaMethodsListSchema,
  type TwoFaMethod,
} from "@simplevault/shared/zod";
import { z } from "zod";

import { request } from "./auth-client";

/**
 * Phase 03 Plan 10 — `/2fa/*` API wrappers consumed by the web 2FA
 * surfaces (`(authed)/settings/security/` and `/login/2fa/`).
 *
 * Reuses the shared `request` helper from `auth-client.ts` — fetch + Zod
 * validation + uniform error envelope handling — so behaviour stays
 * identical to the rest of the API surface.
 *
 * SECURITY (INDEX Key Link 3 — repeated here because it's load-bearing):
 * the TOTP secret is browser-only. The server NEVER sees plaintext. The
 * client encrypts the secret under master_DEK with AAD label
 * AAD_LABEL_TOTP || emailHash (see ./aad-labels) and posts the wrapped blob in
 * `finishTotpRegister`; the server stores the blob opaquely. Same for
 * decrypt: `verifyTotp` decrypts client-side, runs RFC 6238 locally, and
 * posts only the verified `candidateStep`.
 */

// --- Method-list management (auth-required) ------------------------------

export type TwoFaMethodView = TwoFaMethod;

export async function getMethods(accessToken: string): Promise<TwoFaMethodView[]> {
  return request("/2fa/methods", {
    method: "GET",
    schema: TwoFaMethodsListSchema,
    accessToken,
  });
}

/**
 * 204 on success. Server returns 409 `AUTH_2FA_REMOVAL_BLOCKED` when
 * removing this method would leave the user with 0 active 2FA AND they
 * are a member of a shared vault (Phase 03 stub always returns false;
 * Phase 07 flips the dep). Cross-user / unknown id collapses to 404
 * (anti-enumeration — Truth 10).
 */
export async function removeMethod(
  accessToken: string,
  methodId: string,
): Promise<void> {
  await request(`/2fa/methods/${encodeURIComponent(methodId)}`, {
    method: "DELETE",
    schema: z.unknown(),
    accessToken,
  });
}

// --- WebAuthn registration (auth-required) -------------------------------

/**
 * `PublicKeyCredentialCreationOptionsJSON` — emitted verbatim by
 * @simplewebauthn/server@^11. We don't re-validate field-by-field here:
 * the @simplewebauthn/browser library is the only consumer and rejects
 * malformed shapes itself.
 */
const WebauthnRegisterOptionsSchema = z.unknown();

export async function beginWebauthnRegister(accessToken: string): Promise<unknown> {
  return request("/2fa/webauthn/begin-register", {
    method: "POST",
    body: {},
    schema: WebauthnRegisterOptionsSchema,
    accessToken,
  });
}

const WebauthnFinishRegisterResponseSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
});
export type WebauthnFinishRegisterResponse = z.infer<
  typeof WebauthnFinishRegisterResponseSchema
>;

export async function finishWebauthnRegister(
  accessToken: string,
  body: { response: unknown; name: string },
): Promise<WebauthnFinishRegisterResponse> {
  return request("/2fa/webauthn/finish-register", {
    method: "POST",
    body,
    schema: WebauthnFinishRegisterResponseSchema,
    accessToken,
  });
}

// --- WebAuthn authentication (step-up token, NOT access token) -----------

/**
 * Step-up routes carry a `purpose:"2fa-stepup"` JWT issued by /auth/login
 * after 1FA passes. We forward that token via Authorization: Bearer just
 * like an access token; the server's `Require2FAStepUpGuard` validates it.
 */
export async function beginWebauthnAuth(stepUpToken: string): Promise<unknown> {
  return request("/2fa/webauthn/begin-auth", {
    method: "POST",
    body: {},
    schema: z.unknown(),
    accessToken: stepUpToken,
  });
}

/**
 * On success the server mints a full session: refresh cookie set + body
 * carries `accessToken` and the wrapped key material (Phase-02 login parity).
 * Shape is identical to LoginSessionResponseSchema in `auth-client.ts`.
 */
const WebauthnFinishAuthResponseSchema = z.object({
  accessToken: z.string().min(1),
  expiresIn: z.number().int().positive(),
  wrappedMasterDek: z.string().min(1),
  wrappedMasterDekRecovery: z.string().min(1),
  argon2Params: z.object({
    memoryKiB: z.number().int().positive(),
    iterations: z.number().int().positive(),
    parallelism: z.literal(1),
  }),
  serverArgonSalt: z.string().min(1),
  userArgonSalt: z.string().min(1),
  userPubKey: z.string().min(1),
  wrappedUserSigningSk: z.string().min(1),
  wrappedUserKxSk: z.string().min(1),
});
export type WebauthnFinishAuthResponse = z.infer<
  typeof WebauthnFinishAuthResponseSchema
>;

export async function finishWebauthnAuth(
  stepUpToken: string,
  response: unknown,
): Promise<WebauthnFinishAuthResponse> {
  return request("/2fa/webauthn/finish-auth", {
    method: "POST",
    body: { response },
    schema: WebauthnFinishAuthResponseSchema,
    accessToken: stepUpToken,
  });
}

// --- TOTP registration (auth-required, browser-only crypto) --------------

const TotpBeginRegisterResponseSchema = z.object({
  issuanceNonce: z.string().min(1),
});
export type TotpBeginRegisterResponse = z.infer<
  typeof TotpBeginRegisterResponseSchema
>;

export async function beginTotpRegister(
  accessToken: string,
): Promise<TotpBeginRegisterResponse> {
  return request("/2fa/totp/begin-register", {
    method: "POST",
    body: {},
    schema: TotpBeginRegisterResponseSchema,
    accessToken,
  });
}

const TotpFinishRegisterResponseSchema = z.object({
  id: z.string().uuid(),
  name: z.string().min(1),
});
export type TotpFinishRegisterResponse = z.infer<
  typeof TotpFinishRegisterResponseSchema
>;

export interface TotpFinishRegisterRequest {
  issuanceNonce: string;
  /**
   * Base64 of `nonce || ciphertext` (24 B XChaCha20 nonce concatenated with
   * the Poly1305-tagged ciphertext of the secret). Same packing convention
   * as `wrappedMasterDek` on /auth/signup — the server stores the blob as
   * an opaque `bytea`. The client unpacks `nonce` = first 24 bytes,
   * `ciphertext` = rest, then feeds both to AEAD decrypt at /verify time.
   */
  wrappedSecret: string;
  /**
   * Base64 of the AAD bytes used at wrap time: `encodeAad(argon2Params,
   * AAD_LABEL_TOTP || SHA256(lower(email)))`. The client recomputes
   * this at decrypt time too, but storing it server-side lets the server
   * round-trip the bytes without re-deriving them (defence in depth: any
   * mid-stream AAD substitution surfaces as a tag-mismatch on decrypt).
   */
  encryptedSecretAad: string;
  name: string;
  /** RFC 6238 step number that was used to verify the registration code locally. */
  candidateStep: number;
}

export async function finishTotpRegister(
  accessToken: string,
  body: TotpFinishRegisterRequest,
): Promise<TotpFinishRegisterResponse> {
  return request("/2fa/totp/finish-register", {
    method: "POST",
    body,
    schema: TotpFinishRegisterResponseSchema,
    accessToken,
  });
}

// --- TOTP verify (step-up token) -----------------------------------------

/**
 * Returns the same full-session shape as `finishWebauthnAuth` — Truth 7
 * promotes the step-up token to a fully-authenticated session identical to
 * a Phase-02 login.
 */
export async function verifyTotp(
  stepUpToken: string,
  body: { credentialId: string; candidateStep: number },
): Promise<WebauthnFinishAuthResponse> {
  return request("/2fa/totp/verify", {
    method: "POST",
    body,
    schema: WebauthnFinishAuthResponseSchema,
    accessToken: stepUpToken,
  });
}

// --- Step-up material (step-up token) ------------------------------------

/**
 * Phase 03 Plan 10 NEW endpoint — `GET /2fa/step-up-material`. Step-up
 * guarded; returns everything `/login/2fa` needs to complete a TOTP
 * ceremony client-side:
 *   - `userArgonSalt + argon2Params + wrappedMasterDek` — the unwrap
 *     material. The client derives `master_KEK` from the user's already-
 *     typed password + secret_key (preserved in keyStore across the soft
 *     `/login` → `/login/2fa` navigation) and unwraps `master_DEK`.
 *   - `totpCredentials[]` — wrapped TOTP secrets. Client decrypts each
 *     with master_DEK + the stored AAD bytes, runs RFC 6238 locally to
 *     compute the candidate step, and posts to `/2fa/totp/verify`.
 *
 * WebAuthn-only step-up callers don't need this endpoint (the WebAuthn
 * ceremony is server-verified). The web client only invokes it when the
 * step-up response carried `twoFa.totpAvailable === true`.
 *
 * DEVIATION FROM PLAN: the plan called out a narrower
 * `GET /2fa/totp/credentials`; this endpoint folds in the unwrap material
 * to avoid a second roundtrip. Documented in 03-10-SUMMARY.
 */
const StepUpMaterialResponseSchema = z.object({
  userArgonSalt: z.string().min(1),
  argon2Params: z.object({
    memoryKiB: z.number().int().positive(),
    iterations: z.number().int().positive(),
    parallelism: z.literal(1),
  }),
  wrappedMasterDek: z.string().min(1),
  totpCredentials: z.array(
    z.object({
      id: z.string().uuid(),
      name: z.string().min(1),
      /** Base64 of `nonce || ciphertext` — same packing as TotpFinishRegisterRequest. */
      wrappedSecret: z.string().min(1),
      /** Base64 of the AAD bytes used at wrap time. */
      encryptedSecretAad: z.string().min(1),
    }),
  ),
});
export type StepUpMaterialResponse = z.infer<typeof StepUpMaterialResponseSchema>;
export type TotpCredentialForStepUp = StepUpMaterialResponse["totpCredentials"][number];

export async function getStepUpMaterial(
  stepUpToken: string,
): Promise<StepUpMaterialResponse> {
  return request("/2fa/step-up-material", {
    method: "GET",
    schema: StepUpMaterialResponseSchema,
    accessToken: stepUpToken,
  });
}
