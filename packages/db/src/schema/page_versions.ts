import { sql } from "drizzle-orm";
import { index, integer, pgTable, text, timestamp, uuid } from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";
import { pages } from "./pages.js";

/**
 * `page_versions` — Phase 05 ciphertext-snapshot history.
 *
 * Last 10 ciphertext snapshots per page; rotation enforced in
 * `pages.service` PATCH transaction (Plan 05-04). The server stores
 * opaque ciphertext only — same AEAD scheme as `pages` (see pages.ts
 * JSDoc). No `titleSearchToken` here: history rows are not searchable.
 */
export const pageVersions = pgTable(
  "page_versions",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    pageId: uuid("page_id")
      .notNull()
      .references(() => pages.id, { onDelete: "cascade" }),
    version: integer("version").notNull(),
    ciphertext: bytea("ciphertext").notNull(),
    nonce: bytea("nonce").notNull(),
    aadParamsJson: text("aad_params_json").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => ({
    pageVersionIdx: index("page_versions_page_version_idx").on(
      t.pageId,
      sql`${t.version} DESC`,
    ),
  }),
);

export type PageVersion = typeof pageVersions.$inferSelect;
export type NewPageVersion = typeof pageVersions.$inferInsert;
