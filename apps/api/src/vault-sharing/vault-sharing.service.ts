import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { ErrorCodes } from "@simplevault/shared/errors";
import { sql } from "drizzle-orm";

import { DbService } from "../db/db.service.js";

/**
 * Phase 07 / Plan 02 — VaultSharingService.
 *
 * Manages group-vault lifecycle: create, list, invite, accept/decline,
 * member management. The server NEVER touches plaintext vault DEK — all
 * `wrapped_vault_key` fields are opaque base64url blobs that pass through
 * unchanged (server-storage invariant, Truth 7b).
 *
 * Anti-enumeration: cross-user lookups return 404, not 403 (except the
 * explicit owner-vs-member 403 case on invite/remove — a member needs to
 * know they don't have owner rights to give an actionable UX error).
 */

// ─────────────────────────────────────── types

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
  wrappedVaultKey: string; // base64url — only returned to the invitee
  createdAt: string;
}

/** Owner-facing invite summary — omits wrappedVaultKey (FINDING-0066). */
export interface VaultInviteSummary {
  id: string;
  vaultId: string;
  invitedByEmail: string;
  createdAt: string;
}

export interface MemberSummary {
  userId: string;
  email: string;
  role: string;
  joinedAt: string;
}

// ─────────────────────────────────────── row types (raw SQL results)

interface VaultRow {
  id: string;
  name: string | null;
  kind: string;
  owner_user_id: string;
  created_at: Date | string;
  [k: string]: unknown;
}

interface VaultWithMembershipRow {
  vault_id: string;
  vault_name: string | null;
  vault_kind: string;
  vault_created_at: Date | string;
  membership_id: string;
  role: string;
  member_count: number;
  [k: string]: unknown;
}

interface PendingInviteRow {
  id: string;
  vault_id: string;
  vault_name: string | null;
  wrapped_vault_key: Buffer;
  created_at: Date | string;
  invited_by_email: string;
  [k: string]: unknown;
}

interface MemberRow {
  user_id: string;
  email: string;
  role: string;
  joined_at: Date | string;
  [k: string]: unknown;
}

interface UserRow {
  id: string;
  email: string;
  user_pub_key: Buffer;
  [k: string]: unknown;
}

// ─────────────────────────────────────── helpers

function toIso(d: Date | string): string {
  return d instanceof Date ? d.toISOString() : String(d);
}

// ─────────────────────────────────────── service

@Injectable()
export class VaultSharingService {
  constructor(private readonly db: DbService) {}

  /**
   * Create a group vault owned by the caller.
   * Inserts vault row + owner membership row in a transaction.
   */
  async createGroupVault(
    userId: string,
    name: string,
    wrappedVaultKeyB64url: string,
  ): Promise<{ id: string; name: string; kind: string }> {
    if (!name || name.length < 1 || name.length > 100) {
      throw new HttpException(
        { error: { code: ErrorCodes.VALIDATION_FAILED, message: "name must be 1–100 characters" } },
        HttpStatus.BAD_REQUEST,
      );
    }
    const wrappedVaultKey = Buffer.from(wrappedVaultKeyB64url, "base64url");

    return this.db.db.transaction(async (tx) => {
      const vaultResult = await tx.execute<VaultRow>(sql`
        INSERT INTO vaults (kind, name, owner_user_id)
        VALUES ('shared', ${name}, ${userId})
        RETURNING id, name, kind, owner_user_id, created_at
      `);
      const vaultRow = vaultResult.rows[0];
      if (!vaultRow) throw new Error("vault insert returned no row");

      await tx.execute(sql`
        INSERT INTO vault_memberships (vault_id, user_id, role, status, wrapped_vault_key, invited_by)
        VALUES (${vaultRow.id}, ${userId}, 'owner', 'active', ${wrappedVaultKey}, NULL)
      `);

      return { id: vaultRow.id, name: vaultRow.name ?? name, kind: "shared" };
    });
  }

  /**
   * List all vaults the user has access to:
   * - personal vault (owner_user_id = userId AND kind = 'personal')
   * - shared vaults via active membership
   *
   * Returns personal first, then shared vaults by created_at desc.
   */
  async listAllVaults(userId: string): Promise<VaultListItem[]> {
    // Personal vault
    const personalResult = await this.db.db.execute<VaultRow>(sql`
      SELECT id, name, kind, owner_user_id, created_at
      FROM vaults
      WHERE owner_user_id = ${userId} AND kind = 'personal'
      LIMIT 1
    `);

    // Shared vaults via active membership + member count
    const sharedResult = await this.db.db.execute<VaultWithMembershipRow>(sql`
      SELECT
        v.id AS vault_id,
        v.name AS vault_name,
        v.kind AS vault_kind,
        v.created_at AS vault_created_at,
        vm.id AS membership_id,
        vm.role,
        (
          SELECT COUNT(*)::int
          FROM vault_memberships vm2
          WHERE vm2.vault_id = v.id AND vm2.status = 'active'
        ) AS member_count
      FROM vault_memberships vm
      JOIN vaults v ON v.id = vm.vault_id
      WHERE vm.user_id = ${userId} AND vm.status = 'active' AND v.kind = 'shared'
      ORDER BY v.created_at DESC
    `);

    const results: VaultListItem[] = [];

    if (personalResult.rows[0]) {
      results.push({
        id: personalResult.rows[0].id,
        name: null,
        kind: "personal",
        role: "owner",
        memberCount: 1,
      });
    }

    for (const row of sharedResult.rows) {
      results.push({
        id: row.vault_id,
        name: row.vault_name,
        kind: "shared",
        role: row.role as "owner" | "member",
        memberCount: row.member_count,
      });
    }

    return results;
  }

  /**
   * Lookup a user by email to get their public key for key wrapping.
   * Anti-enumeration: requester's own email returns same 404 as not found.
   */
  async lookupUser(
    requesterId: string,
    email: string,
  ): Promise<{ id: string; kxPublicKey: string }> {
    const result = await this.db.db.execute<UserRow>(sql`
      SELECT id, email, user_pub_key
      FROM users
      WHERE lower(email) = lower(${email})
      LIMIT 1
    `);
    const user = result.rows[0];
    // Anti-enumeration: if not found OR found user is the requester → same 404
    if (!user || user.id === requesterId) {
      throw new HttpException(
        { error: { code: ErrorCodes.VAULT_USER_NOT_FOUND, message: "User not found" } },
        HttpStatus.NOT_FOUND,
      );
    }
    return {
      id: user.id,
      kxPublicKey: Buffer.from(user.user_pub_key).toString("base64url"),
    };
  }

  /**
   * Create an invite for a user to join a vault.
   * Requester must be an active owner of the vault.
   * Throws 409 if the invitee is already a member (or has a pending invite).
   */
  async createInvite(
    ownerId: string,
    vaultId: string,
    inviteeId: string,
    wrappedVaultKeyB64url: string,
  ): Promise<void> {
    // Verify requester has role='owner' AND status='active' — treat not-found as denied (anti-enum)
    const ownerCheck = await this.db.db.execute<{ id: string }>(sql`
      SELECT id FROM vault_memberships
      WHERE vault_id = ${vaultId} AND user_id = ${ownerId} AND role = 'owner' AND status = 'active'
      LIMIT 1
    `);
    if (!ownerCheck.rows[0]) {
      throw new HttpException(
        { error: { code: ErrorCodes.VAULT_SHARING_ACCESS_DENIED, message: "Access denied" } },
        HttpStatus.FORBIDDEN,
      );
    }

    const wrappedVaultKey = Buffer.from(wrappedVaultKeyB64url, "base64url");

    try {
      await this.db.db.execute(sql`
        INSERT INTO vault_memberships (vault_id, user_id, role, status, wrapped_vault_key, invited_by)
        VALUES (${vaultId}, ${inviteeId}, 'member', 'pending', ${wrappedVaultKey}, ${ownerId})
      `);
    } catch (err) {
      // Postgres unique constraint violation: code 23505
      if (
        err &&
        typeof err === "object" &&
        "code" in err &&
        (err as { code: string }).code === "23505"
      ) {
        throw new HttpException(
          { error: { code: ErrorCodes.VAULT_ALREADY_MEMBER, message: "User is already a member or has a pending invite" } },
          HttpStatus.CONFLICT,
        );
      }
      throw err;
    }
  }

  /**
   * Get pending invites for the authenticated user (as invitee).
   */
  async getPendingInvitesForUser(userId: string): Promise<PendingInvite[]> {
    const result = await this.db.db.execute<PendingInviteRow>(sql`
      SELECT
        vm.id,
        vm.vault_id,
        v.name AS vault_name,
        vm.wrapped_vault_key,
        vm.created_at,
        u.email AS invited_by_email
      FROM vault_memberships vm
      JOIN vaults v ON v.id = vm.vault_id
      JOIN users u ON u.id = vm.invited_by
      WHERE vm.user_id = ${userId} AND vm.status = 'pending'
      ORDER BY vm.created_at DESC
    `);

    return result.rows.map((row) => ({
      id: row.id,
      vaultId: row.vault_id,
      vaultName: row.vault_name,
      invitedByEmail: row.invited_by_email,
      wrappedVaultKey: Buffer.from(row.wrapped_vault_key).toString("base64url"),
      createdAt: toIso(row.created_at),
    }));
  }

  /**
   * Accept a pending invite. Only the invitee can accept their own invite.
   */
  async acceptInvite(userId: string, inviteId: string): Promise<void> {
    const result = await this.db.db.execute<{ id: string }>(sql`
      UPDATE vault_memberships
      SET status = 'active', updated_at = now()
      WHERE id = ${inviteId} AND user_id = ${userId} AND status = 'pending'
      RETURNING id
    `);
    if (result.rows.length === 0) {
      throw new HttpException(
        { error: { code: ErrorCodes.VAULT_INVITE_NOT_FOUND, message: "Invite not found" } },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  /**
   * Decline a pending invite. Only the invitee can decline their own invite.
   */
  async declineInvite(userId: string, inviteId: string): Promise<void> {
    const result = await this.db.db.execute<{ id: string }>(sql`
      UPDATE vault_memberships
      SET status = 'revoked', updated_at = now()
      WHERE id = ${inviteId} AND user_id = ${userId} AND status = 'pending'
      RETURNING id
    `);
    if (result.rows.length === 0) {
      throw new HttpException(
        { error: { code: ErrorCodes.VAULT_INVITE_NOT_FOUND, message: "Invite not found" } },
        HttpStatus.NOT_FOUND,
      );
    }
  }

  /**
   * List all active members of a vault.
   * Requester must be an active member (any role).
   */
  async listActiveMembers(requesterId: string, vaultId: string): Promise<MemberSummary[]> {
    // Verify requester is an active member
    const access = await this.db.db.execute<{ id: string }>(sql`
      SELECT id FROM vault_memberships
      WHERE vault_id = ${vaultId} AND user_id = ${requesterId} AND status = 'active'
      LIMIT 1
    `);
    if (!access.rows[0]) {
      throw new HttpException(
        { error: { code: ErrorCodes.VAULT_SHARING_NOT_FOUND, message: "Vault not found" } },
        HttpStatus.NOT_FOUND,
      );
    }

    const result = await this.db.db.execute<MemberRow>(sql`
      SELECT
        vm.user_id,
        u.email,
        vm.role,
        vm.created_at AS joined_at
      FROM vault_memberships vm
      JOIN users u ON u.id = vm.user_id
      WHERE vm.vault_id = ${vaultId} AND vm.status = 'active'
      ORDER BY vm.created_at ASC
    `);

    return result.rows.map((row) => ({
      userId: row.user_id,
      email: row.email,
      role: row.role,
      joinedAt: toIso(row.joined_at),
    }));
  }

  /**
   * Remove a member from a vault (or let a member leave voluntarily).
   * - Self-removal: only needs to be an active member.
   * - Remove others: requester must be an active owner.
   * - Last-owner guard: cannot remove the last active owner.
   *
   * The access check, last-owner guard, and DELETE all run inside one
   * transaction. The `SELECT ... FOR UPDATE` on the target row prevents a
   * TOCTOU race between the owner-count check and the DELETE (FINDING-0060).
   */
  async removeMember(
    requesterId: string,
    vaultId: string,
    targetUserId: string,
  ): Promise<void> {
    type Tx = { execute: <T>(s: unknown) => Promise<{ rows: T[] }> };
    const db = this.db.db as unknown as { transaction: <T>(cb: (tx: Tx) => Promise<T>) => Promise<T> };

    await db.transaction(async (tx) => {
      // Verify requester has permission
      if (requesterId === targetUserId) {
        const access = await tx.execute<{ id: string }>(sql`
          SELECT id FROM vault_memberships
          WHERE vault_id = ${vaultId} AND user_id = ${requesterId} AND status = 'active'
          LIMIT 1
        `);
        if (!access.rows[0]) {
          throw new HttpException(
            { error: { code: ErrorCodes.VAULT_SHARING_NOT_FOUND, message: "Vault not found" } },
            HttpStatus.NOT_FOUND,
          );
        }
      } else {
        const ownerCheck = await tx.execute<{ id: string }>(sql`
          SELECT id FROM vault_memberships
          WHERE vault_id = ${vaultId} AND user_id = ${requesterId} AND role = 'owner' AND status = 'active'
          LIMIT 1
        `);
        if (!ownerCheck.rows[0]) {
          throw new HttpException(
            { error: { code: ErrorCodes.VAULT_SHARING_ACCESS_DENIED, message: "Access denied" } },
            HttpStatus.FORBIDDEN,
          );
        }
      }

      // Lock the target membership row to prevent concurrent removes
      const targetLock = await tx.execute<{ id: string; role: string }>(sql`
        SELECT id, role FROM vault_memberships
        WHERE vault_id = ${vaultId} AND user_id = ${targetUserId} AND status = 'active'
        LIMIT 1
        FOR UPDATE
      `);
      const targetRow = targetLock.rows[0];
      if (!targetRow) {
        throw new HttpException(
          { error: { code: ErrorCodes.VAULT_SHARING_NOT_FOUND, message: "Member not found" } },
          HttpStatus.NOT_FOUND,
        );
      }

      // Last-owner guard — also locked to prevent two concurrent last-owner removals
      if (targetRow.role === "owner") {
        const ownerCount = await tx.execute<{ n: number }>(sql`
          SELECT COUNT(*)::int AS n
          FROM vault_memberships
          WHERE vault_id = ${vaultId} AND role = 'owner' AND status = 'active'
          FOR UPDATE
        `);
        const count = ownerCount.rows[0]?.n ?? 0;
        const countNum = typeof count === "number" ? count : Number(count);
        if (countNum <= 1) {
          throw new HttpException(
            { error: { code: ErrorCodes.VAULT_SHARING_ACCESS_DENIED, message: "Cannot remove the last owner" } },
            HttpStatus.CONFLICT,
          );
        }
      }

      await tx.execute(sql`
        DELETE FROM vault_memberships
        WHERE vault_id = ${vaultId} AND user_id = ${targetUserId} AND status = 'active'
      `);
    });
  }

  /**
   * Get pending invites sent for a vault (owner view).
   * Requester must be an active owner.
   */
  async getVaultInvites(requesterId: string, vaultId: string): Promise<VaultInviteSummary[]> {
    // Verify requester is an active owner
    const ownerCheck = await this.db.db.execute<{ id: string }>(sql`
      SELECT id FROM vault_memberships
      WHERE vault_id = ${vaultId} AND user_id = ${requesterId} AND role = 'owner' AND status = 'active'
      LIMIT 1
    `);
    if (!ownerCheck.rows[0]) {
      throw new HttpException(
        { error: { code: ErrorCodes.VAULT_SHARING_NOT_FOUND, message: "Vault not found" } },
        HttpStatus.NOT_FOUND,
      );
    }

    const result = await this.db.db.execute<PendingInviteRow>(sql`
      SELECT
        vm.id,
        vm.vault_id,
        v.name AS vault_name,
        vm.wrapped_vault_key,
        vm.created_at,
        u.email AS invited_by_email
      FROM vault_memberships vm
      JOIN vaults v ON v.id = vm.vault_id
      JOIN users u ON u.id = vm.invited_by
      WHERE vm.vault_id = ${vaultId} AND vm.status = 'pending'
      ORDER BY vm.created_at DESC
    `);

    return result.rows.map((row) => ({
      id: row.id,
      vaultId: row.vault_id,
      invitedByEmail: row.invited_by_email,
      createdAt: toIso(row.created_at),
    }));
  }
}
