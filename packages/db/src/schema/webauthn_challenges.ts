import { index, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

import { bytea } from "./_bytea.js";
import { users } from "./users.js";

/**
 * `webauthn_challenges` — short-lived nonces for WebAuthn ceremonies.
 *
 * Two `kind` values (enforced at app layer): `"register"` for
 * `/2fa/webauthn/begin-register` flows and `"auth"` for
 * `/2fa/webauthn/begin-auth` flows.
 *
 * SECURITY (Phase 03 — Key Link 2):
 *   - `challenge` is 32 random bytes from `crypto.randomBytes` / `randombytes_buf`.
 *   - The unique `(user_id, kind)` index enforces "at most one in-flight
 *     ceremony per kind" — calling begin-* twice replaces the prior row
 *     (UPSERT at the app layer).
 *   - The finish-* endpoint MUST consume atomically with
 *     `DELETE FROM webauthn_challenges WHERE id = $1 RETURNING challenge`.
 *     NEVER look-up-then-delete (TOCTOU race; double-redemption opens replay).
 *   - TTL is enforced at the app layer (compare `expires_at` to `now()` in
 *     the same DELETE). `expires_at` index supports a future opportunistic
 *     sweep cron, but Phase 03 does not need it.
 */
export const webauthnChallenges = pgTable(
  "webauthn_challenges",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    /** "register" or "auth". Enum at app layer. */
    kind: text("kind").notNull(),
    /** 32 random bytes. NEVER reused across users or kinds. */
    challenge: bytea("challenge").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  },
  (t) => ({
    userKindIdx: uniqueIndex("webauthn_challenges_user_kind_idx").on(t.userId, t.kind),
    expiresIdx: index("webauthn_challenges_expires_idx").on(t.expiresAt),
  }),
);

export type WebauthnChallenge = typeof webauthnChallenges.$inferSelect;
export type NewWebauthnChallenge = typeof webauthnChallenges.$inferInsert;
