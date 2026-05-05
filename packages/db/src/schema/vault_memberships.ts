import { check, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

import { bytea } from "./_bytea.js";
import { users } from "./users.js";
import { vaults } from "./vaults.js";

/**
 * Phase 07 — per-member sealed vault DEK storage.
 *
 * Each row holds one member's copy of the vault DEK, sealed under their
 * X25519 public key via `crypto_box_seal`. Server NEVER sees the DEK.
 *
 * wrappedVaultKey = sealed_box(vault_dek, member.user_pub_key) — 48 bytes
 * (32-byte key + 16-byte MAC overhead for X25519+XSalsa20-Poly1305).
 */
export const vaultMemberships = pgTable(
  "vault_memberships",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    vaultId: uuid("vault_id")
      .notNull()
      .references(() => vaults.id, { onDelete: "cascade" }),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    role: text("role").notNull(),
    status: text("status").notNull().default("pending"),
    /** sealed_box(vault_DEK, member.user_pub_key) — opaque bytes, never decrypted server-side. */
    wrappedVaultKey: bytea("wrapped_vault_key").notNull(),
    invitedBy: uuid("invited_by").references(() => users.id),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    vaultUserUidx: uniqueIndex("vault_memberships_vault_user_uidx").on(
      t.vaultId,
      t.userId,
    ),
    roleCheck: check(
      "vault_memberships_role_check",
      sql`${t.role} IN ('owner','member')`,
    ),
    statusCheck: check(
      "vault_memberships_status_check",
      sql`${t.status} IN ('pending','active','revoked')`,
    ),
  }),
);

export type VaultMembership = typeof vaultMemberships.$inferSelect;
export type NewVaultMembership = typeof vaultMemberships.$inferInsert;
