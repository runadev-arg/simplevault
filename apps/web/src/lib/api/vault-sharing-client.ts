import { z } from "zod";

import { AuthClientError, request } from "./auth-client";
import { b64UrlToBytes, bytesToB64Url } from "./base64url";

/**
 * Phase 07 / Plan 07-04 — typed wrappers for the vault-sharing REST surface.
 *
 * All wrappers go through the existing `request` helper from auth-client.ts
 * (Phase-02 wrapper that owns fetch / Zod-validate / error-envelope plumbing).
 *
 * Wire shape:
 *   - `wrappedVaultKey` travels as a base64url-encoded string.
 *   - On send: callers pass `Uint8Array`; wrapper encodes via `bytesToB64Url`.
 *   - On receive: wrapper decodes via `b64UrlToBytes` → `Uint8Array`.
 */

// --- error subclasses --------------------------------------------------------

export class VaultSharingNotFoundError extends AuthClientError {
  constructor(message = "Vault not found") {
    super({ code: "VAULT_NOT_FOUND", message, status: 404 });
    this.name = "VaultSharingNotFoundError";
  }
}

export class VaultAlreadyMemberError extends AuthClientError {
  constructor(message = "User is already a member of this vault") {
    super({ code: "VAULT_ALREADY_MEMBER", message, status: 409 });
    this.name = "VaultAlreadyMemberError";
  }
}

export class VaultAccessDeniedError extends AuthClientError {
  constructor(message = "Access denied") {
    super({ code: "VAULT_ACCESS_DENIED", message, status: 403 });
    this.name = "VaultAccessDeniedError";
  }
}

export class VaultUserNotFoundError extends AuthClientError {
  constructor(message = "User not found") {
    super({ code: "VAULT_USER_NOT_FOUND", message, status: 404 });
    this.name = "VaultUserNotFoundError";
  }
}

// --- Zod schemas for response parsing ----------------------------------------

const VaultListItemSchema = z.object({
  id: z.string().uuid(),
  name: z.string().nullable(),
  kind: z.enum(["personal", "shared"]),
  role: z.enum(["owner", "member"]),
  memberCount: z.number().int().min(0),
});

const PendingInviteSchema = z.object({
  id: z.string().uuid(),
  vaultId: z.string().uuid(),
  vaultName: z.string().nullable(),
  invitedByEmail: z.string(),
  wrappedVaultKey: z.string(), // base64url
  createdAt: z.string(),
});

const MemberSummarySchema = z.object({
  userId: z.string().uuid(),
  email: z.string(),
  role: z.string(),
  joinedAt: z.string(),
});

const UserLookupSchema = z.object({
  id: z.string().uuid(),
  kxPublicKey: z.string(), // base64url
});

// --- public types ------------------------------------------------------------

export interface VaultListItem {
  id: string;
  name: string | null;
  kind: "personal" | "shared";
  role: "owner" | "member";
  memberCount: number;
}

export interface PendingInvite {
  id: string;
  vaultId: string;
  vaultName: string | null;
  invitedByEmail: string;
  wrappedVaultKey: Uint8Array; // decoded from base64url
  createdAt: string;
}

export interface MemberSummary {
  userId: string;
  email: string;
  role: string;
  joinedAt: string;
}

// --- wrappers ----------------------------------------------------------------

/**
 * `GET /vaults` — list all vaults the caller has access to (personal +
 * shared). Returns metadata only (no DEKs).
 */
export async function listAllVaults(
  accessToken: string,
): Promise<VaultListItem[]> {
  return request("/vaults", {
    method: "GET",
    schema: z.array(VaultListItemSchema),
    accessToken,
  });
}

/**
 * `POST /vaults/group` — create a new shared vault. The caller provides the
 * vault DEK pre-wrapped under their own X25519 public key (sealed box).
 */
export async function createGroupVault(
  accessToken: string,
  name: string,
  wrappedVaultKey: Uint8Array,
): Promise<{ id: string; name: string | null }> {
  return request("/vaults/group", {
    method: "POST",
    body: {
      name,
      wrappedVaultKey: bytesToB64Url(wrappedVaultKey),
    },
    schema: z.object({ id: z.string().uuid(), name: z.string().nullable() }),
    accessToken,
  });
}

/**
 * `GET /users/lookup?email=...` — look up a user by email to obtain their
 * X25519 public key for vault-DEK wrapping before sending an invite.
 */
export async function lookupUser(
  accessToken: string,
  email: string,
): Promise<{ id: string; kxPublicKey: Uint8Array }> {
  const raw = await request(
    `/users/lookup?email=${encodeURIComponent(email)}`,
    {
      method: "GET",
      schema: UserLookupSchema,
      accessToken,
    },
  );
  return {
    id: raw.id,
    kxPublicKey: b64UrlToBytes(raw.kxPublicKey),
  };
}

/**
 * `POST /vaults/:vaultId/invites` — create an invite for a user. The caller
 * must first look up the invitee's X25519 public key via `lookupUser`, wrap
 * the vault DEK under it, and pass the sealed box here.
 */
export async function createInvite(
  accessToken: string,
  vaultId: string,
  inviteeId: string,
  wrappedVaultKey: Uint8Array,
): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultId)}/invites`, {
    method: "POST",
    body: {
      inviteeId,
      wrappedVaultKey: bytesToB64Url(wrappedVaultKey),
    },
    schema: z.unknown(),
    accessToken,
  });
}

/**
 * `GET /invites` — list pending invites for the caller.
 * Returns the wrapped vault key decoded from base64url to `Uint8Array`.
 */
export async function getPendingInvites(
  accessToken: string,
): Promise<PendingInvite[]> {
  const raw = await request("/invites", {
    method: "GET",
    schema: z.array(PendingInviteSchema),
    accessToken,
  });
  return raw.map((r) => ({
    id: r.id,
    vaultId: r.vaultId,
    vaultName: r.vaultName,
    invitedByEmail: r.invitedByEmail,
    wrappedVaultKey: b64UrlToBytes(r.wrappedVaultKey),
    createdAt: r.createdAt,
  }));
}

/**
 * `POST /invites/:inviteId/accept` — accept a pending invite.
 * After acceptance the caller should load the wrapped vault key, unwrap it
 * with their X25519 secret key, and store the result in keyStore under
 * `"vault_dek:${vaultId}"`.
 */
export async function acceptInvite(
  accessToken: string,
  inviteId: string,
): Promise<void> {
  await request(`/invites/${encodeURIComponent(inviteId)}/accept`, {
    method: "POST",
    schema: z.unknown(),
    accessToken,
  });
}

/**
 * `POST /invites/:inviteId/decline` — decline a pending invite.
 */
export async function declineInvite(
  accessToken: string,
  inviteId: string,
): Promise<void> {
  await request(`/invites/${encodeURIComponent(inviteId)}/decline`, {
    method: "POST",
    schema: z.unknown(),
    accessToken,
  });
}

/**
 * `GET /vaults/:vaultId/members` — list members of a shared vault.
 * Caller must be the vault owner or a member.
 */
export async function listMembers(
  accessToken: string,
  vaultId: string,
): Promise<MemberSummary[]> {
  return request(`/vaults/${encodeURIComponent(vaultId)}/members`, {
    method: "GET",
    schema: z.array(MemberSummarySchema),
    accessToken,
  });
}

/**
 * `DELETE /vaults/:vaultId/members/:userId` — remove a member from a vault.
 * Only the vault owner may call this.
 */
export async function removeMember(
  accessToken: string,
  vaultId: string,
  userId: string,
): Promise<void> {
  await request(
    `/vaults/${encodeURIComponent(vaultId)}/members/${encodeURIComponent(userId)}`,
    {
      method: "DELETE",
      schema: z.unknown(),
      accessToken,
    },
  );
}
