import { sql } from "drizzle-orm";
import { check, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

import { users } from "./users.js";

/**
 * `vaults` — Phase 04 personal/shared vault root.
 *
 * SECURITY INVARIANT (Truth 19 — SQL-level IDOR primitive):
 * Personal-vault routes (`GET /vault/personal`, etc.) NEVER take a `:id`
 * parameter. They look up by `(owner_user_id = req.user.id, kind = 'personal')`
 * — and the unique partial index `vaults_owner_personal_uidx` guarantees at
 * most one such row per user. IDOR is impossible by construction at the SQL
 * level: there is no way to address another user's personal vault, because
 * the only addressing primitive is the authenticated user's own id.
 *
 * Shared vaults (Phase 07) reuse the same row with `kind = 'shared'`; the
 * partial index intentionally does NOT cover those, since one user may own
 * multiple shared vaults.
 */
export const vaults = pgTable(
  "vaults",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    ownerUserId: uuid("owner_user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    kind: text("kind").notNull().default("personal"),
    /** Display name — null for personal vaults; required for shared vaults. */
    name: text("name"),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    ownerPersonalUidx: uniqueIndex("vaults_owner_personal_uidx")
      .on(t.ownerUserId)
      .where(sql`${t.kind} = 'personal'`),
    kindCheck: check("vaults_kind_check", sql`${t.kind} IN ('personal','shared')`),
  }),
);

export type Vault = typeof vaults.$inferSelect;
export type NewVault = typeof vaults.$inferInsert;
