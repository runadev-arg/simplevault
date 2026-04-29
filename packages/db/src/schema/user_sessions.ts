import { sql } from "drizzle-orm";
import {
  type AnyPgColumn,
  index,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";
import { users } from "./users.js";

/**
 * `user_sessions` — refresh-token rotation lineage.
 *
 * One row per refresh token ever issued. New login -> new `family_id` (UUID).
 * Each rotation inserts a new row with the old row's id in `prev_token_id`
 * and bumps `used_at` on the old row. Reuse of an already-rotated token is
 * detected via `used_at IS NOT NULL` -> family-revoke (the API in 02-08
 * UPDATEs `revoked_at = now()` for ALL rows where `family_id = X AND
 * revoked_at IS NULL`).
 *
 * SECURITY: `refresh_token_hash` is BLAKE2b-256 of the raw refresh token.
 * Refresh tokens are high-entropy random bytes (>= 256 bits), so a fast
 * integrity-only hash is correct here — slow KDFs (Argon2/bcrypt) would
 * waste CPU on every refresh without adding meaningful resistance.
 * The raw token NEVER touches the database.
 */
export const userSessions = pgTable(
  "user_sessions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    /** UUID shared across all rotations of one login session lineage. */
    familyId: uuid("family_id").notNull(),
    /** BLAKE2b-256(raw_refresh_token). Never the raw token. */
    refreshTokenHash: bytea("refresh_token_hash").notNull(),
    /** Self-ref to the previous row in the rotation chain. NULL on initial login. */
    prevTokenId: uuid("prev_token_id").references((): AnyPgColumn => userSessions.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    /** Set on rotation. If non-null AND token presented again -> reuse-detect. */
    usedAt: timestamp("used_at", { withTimezone: true }),
    /** Set on logout, family-revoke, or reuse-detect. */
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    userAgentFamily: text("user_agent_family"),
    /** HMAC of client IP (privacy-preserving — never raw IP). */
    ipHash: bytea("ip_hash"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (t) => ({
    /** Lookup by token hash on every refresh. */
    refreshHashIdx: uniqueIndex("user_sessions_refresh_hash_idx").on(t.refreshTokenHash),
    /** Active-session listing for /me — partial index on non-revoked rows only. */
    userActiveIdx: index("user_sessions_user_active_idx")
      .on(t.userId)
      .where(sql`revoked_at IS NULL`),
    /** Family-revoke target index. */
    familyIdx: index("user_sessions_family_idx").on(t.familyId),
  }),
);

export type UserSession = typeof userSessions.$inferSelect;
export type NewUserSession = typeof userSessions.$inferInsert;
