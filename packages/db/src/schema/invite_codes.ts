import { sql } from "drizzle-orm";
import {
  index,
  pgTable,
  timestamp,
  uniqueIndex,
  uuid,
  varchar,
} from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";
import { users } from "./users.js";

/**
 * `invite_codes` — operator-issued, single-use signup codes.
 *
 * The CLI in 02-06 inserts rows here (it generates a raw code, prints it
 * once to stdout, stores ONLY the HMAC). The signup endpoint in 02-07
 * redeems them (constant-time HMAC compare against `code_hash`, then
 * UPDATE `redeemed_at = now()`, `redeemed_user_id = <new_user>`).
 *
 * SECURITY:
 *   code_hash = HMAC-SHA256(SERVER_INVITE_SECRET, raw_code)
 * The raw code never touches the database. SERVER_INVITE_SECRET pepper
 * means a DB-only compromise can't precompute/rainbow-table the codes.
 *
 * `email` is stored lowercased — same case-insensitive convention as
 * `users.email`. v1 uses lower(email) explicitly rather than the citext
 * extension (one less PG extension dependency, see 01-08-COMPAT.md).
 *
 * `created_by` is nullable for v1 because the operator is not yet a
 * regular user (no operator account in `users`). Wire it up in a later
 * phase when admin-as-user lands.
 */
export const inviteCodes = pgTable(
  "invite_codes",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    /** HMAC-SHA256(SERVER_INVITE_SECRET, raw_code). Never the raw code. */
    codeHash: bytea("code_hash").notNull(),
    /**
     * Lowercased on insert by the issuing CLI.
     * RFC 5321 ceiling — also bounds throttler login-email Redis key length
     * (FINDING-0017 storage-tier fix; FINDING-0022 partial mitigation).
     */
    email: varchar("email", { length: 254 }).notNull(),
    /** Operator user_id; nullable until admin-as-user exists. */
    createdBy: uuid("created_by"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    redeemedAt: timestamp("redeemed_at", { withTimezone: true }),
    redeemedUserId: uuid("redeemed_user_id").references(() => users.id, {
      onDelete: "set null",
    }),
  },
  (t) => ({
    codeHashIdx: uniqueIndex("invite_codes_code_hash_idx").on(t.codeHash),
    /** Operator may re-issue codes to the same address — non-unique. */
    emailLowerIdx: index("invite_codes_email_lower_idx").on(sql`lower(${t.email})`),
    /** Fast scan over outstanding (unredeemed, unexpired) codes — partial index. */
    outstandingIdx: index("invite_codes_outstanding_idx")
      .on(t.expiresAt)
      .where(sql`redeemed_at IS NULL`),
  }),
);

export type InviteCode = typeof inviteCodes.$inferSelect;
export type NewInviteCode = typeof inviteCodes.$inferInsert;
