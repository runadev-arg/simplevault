import { z } from "zod";

import { request } from "./auth-client";
import { b64UrlToBytes, bytesToB64Url } from "./base64url";

/**
 * Phase 04 / Plan 06 — typed wrappers for the credentials + personal-vault
 * REST surface.
 *
 * All wrappers go through the existing `request` helper from auth-client.ts
 * (the project's Phase-02 wrapper that owns fetch / Zod-validate /
 * error-envelope plumbing). NO duplicate fetch logic lives here.
 *
 * Wire shape (load-bearing, mirrors Plan 04-02 DTOs):
 *   - `ciphertext` and `nonce` travel as base64url-encoded strings.
 *   - On send: callers pass `Uint8Array`; wrapper encodes via `bytesToB64Url`.
 *   - On receive: wrapper decodes via `b64UrlToBytes` → `Uint8Array`.
 *
 * 409 → typed `VersionConflictError` mapping (see errors.ts) is hooked in
 * Plan 04-06 Task 2 — that's the load-bearing handoff to Plan 04-10's edit
 * form retry UX.
 */

// --- response schemas ----------------------------------------------------

/**
 * Server returns ciphertext / nonce as base64url-encoded strings (per
 * Plan 04-02 contract). Empty/short ones are not legal — DTO enforces
 * `min(1)` server-side.
 */
const CredentialResponseWireSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  version: z.number().int().nonnegative(),
  ciphertext: z.string().min(1),
  nonce: z.string().min(1),
  aadParamsJson: z.string().min(1),
  updatedAt: z.string(),
});

const CredentialSummaryWireSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  version: z.number().int().nonnegative(),
  updatedAt: z.string(),
});

const VaultPersonalResponseSchema = z.object({
  vaultId: z.string().uuid(),
  credentialIds: z.array(
    z.object({
      id: z.string().uuid(),
      version: z.number().int().nonnegative(),
      updatedAt: z.string(),
    }),
  ),
});

// --- public types --------------------------------------------------------

export interface CredentialBlob {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
}

export interface CredentialResponse extends CredentialBlob {
  id: string;
  vaultId: string;
  version: number;
  updatedAt: string;
}

export interface CredentialSummary {
  id: string;
  vaultId: string;
  version: number;
  updatedAt: string;
}

export interface VaultPersonalResponse {
  vaultId: string;
  credentialIds: { id: string; version: number; updatedAt: string }[];
}

export interface CreateCredentialInput {
  vaultId: string;
  credentialId?: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
}

export interface UpdateCredentialInput {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
  aadParamsJson: string;
  /** CAS-witness: caller's known-current version. Stale → 409 → VersionConflictError. */
  version: number;
}

// --- wrappers ------------------------------------------------------------

/**
 * `GET /vault/personal` — METADATA-ONLY listing of the caller's personal
 * vault (Plan 04-03). No ciphertext / nonce / AAD here; UI fans out
 * `getCredential(id)` per visible card.
 */
export async function listVaultPersonal(
  accessToken: string,
): Promise<VaultPersonalResponse> {
  return request("/vault/personal", {
    method: "GET",
    schema: VaultPersonalResponseSchema,
    accessToken,
  });
}

/**
 * `POST /credentials` — create. Server returns the freshly-minted row's
 * id / vaultId / version / updatedAt (no blob in the 201 body — re-read
 * via `getCredential` if the caller needs the round-trip).
 */
export async function createCredential(
  accessToken: string,
  input: CreateCredentialInput,
): Promise<CredentialSummary> {
  return request("/credentials", {
    method: "POST",
    body: {
      vaultId: input.vaultId,
      ...(input.credentialId !== undefined ? { credentialId: input.credentialId } : {}),
      ciphertext: bytesToB64Url(input.ciphertext),
      nonce: bytesToB64Url(input.nonce),
      aadParamsJson: input.aadParamsJson,
      version: 1,
    },
    schema: CredentialSummaryWireSchema,
    accessToken,
  });
}

/**
 * `GET /credentials/:id` — read. Decodes ciphertext + nonce from base64url
 * back to `Uint8Array` so callers stay in the bytes-only world before
 * handing off to `credential-cipher.ts`.
 *
 * Cross-user / unknown id → uniform 404 `CREDENTIAL_NOT_FOUND` (Truth 3
 * anti-enumeration); surfaces as `CredentialNotFoundError` after Plan-06
 * Task 2's mapping ships.
 */
export async function getCredential(
  accessToken: string,
  id: string,
): Promise<CredentialResponse> {
  const raw = await request(`/credentials/${encodeURIComponent(id)}`, {
    method: "GET",
    schema: CredentialResponseWireSchema,
    accessToken,
  });
  return {
    id: raw.id,
    vaultId: raw.vaultId,
    version: raw.version,
    ciphertext: b64UrlToBytes(raw.ciphertext),
    nonce: b64UrlToBytes(raw.nonce),
    aadParamsJson: raw.aadParamsJson,
    updatedAt: raw.updatedAt,
  };
}

/**
 * `PATCH /credentials/:id` — atomic CAS update. `input.version` is the
 * caller's known-current value; stale → 409 → typed `VersionConflictError`
 * (mapping in Task 2; this wrapper rewraps the generic ApiError so the
 * thrown error carries the credential id for Plan 04-10's retry UX).
 */
export async function updateCredential(
  accessToken: string,
  id: string,
  input: UpdateCredentialInput,
): Promise<CredentialSummary> {
  return request(`/credentials/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: {
      ciphertext: bytesToB64Url(input.ciphertext),
      nonce: bytesToB64Url(input.nonce),
      aadParamsJson: input.aadParamsJson,
      version: input.version,
    },
    schema: CredentialSummaryWireSchema,
    accessToken,
  });
}

/**
 * `DELETE /credentials/:id` — 204 on success. Cross-user / unknown id →
 * uniform 404 (anti-enumeration).
 */
export async function deleteCredential(
  accessToken: string,
  id: string,
): Promise<void> {
  await request(`/credentials/${encodeURIComponent(id)}`, {
    method: "DELETE",
    schema: z.unknown(),
    accessToken,
  });
}
