import { sql } from "drizzle-orm";
import {
  bigint,
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
 * `webauthn_credentials` — one row per registered passkey.
 *
 * SECURITY (Phase 03 — REQ-2FA-001):
 *   - `credential_id` is the WebAuthn-side primary key (base64url-decoded
 *     bytes); MUST be globally unique to satisfy passkey discovery.
 *   - `public_key` is COSE-encoded; stored opaquely — `@simplewebauthn/server`
 *     parses it on every assertion verification.
 *   - `counter` MUST monotonically increase across assertions. A regression
 *     (incoming counter <= stored) is treated as clone-detection and rejected
 *     with `auth.2fa.webauthn.auth.fail` audit event (reason `counter_regression`).
 *   - `aaguid` is informational (vendor identification) and NEVER used for
 *     authorisation decisions in v1.
 *
 * The RP ID this credential was registered under is implicit from the
 * deployment env (`WEBAUTHN_RP_ID`); changing RP ID is a data-migration
 * event (every passkey BREAKS and must be re-registered).
 */
export const webauthnCredentials = pgTable(
  "webauthn_credentials",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    userId: uuid("user_id")
      .notNull()
      .references(() => users.id, { onDelete: "cascade" }),
    /** WebAuthn credential ID — globally unique per passkey. base64url-decoded bytes. */
    credentialId: bytea("credential_id").notNull(),
    /** Authenticator's public key (COSE-encoded — store opaquely). */
    publicKey: bytea("public_key").notNull(),
    /** Counter — must monotonically increase. Regression = clone-detection trigger. */
    counter: bigint("counter", { mode: "number" }).notNull().default(0),
    /** Authenticator-hint subset of `["usb","nfc","ble","internal","hybrid"]`. */
    transports: text("transports")
      .array()
      .notNull()
      .default(sql`'{}'::text[]`),
    /** Authenticator AAGUID for vendor identification (informational). */
    aaguid: bytea("aaguid"),
    /** User-chosen name e.g. "iCloud Keychain" / "YubiKey 5C". 1..64 chars. */
    name: text("name").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    lastUsedAt: timestamp("last_used_at", { withTimezone: true }),
  },
  (t) => ({
    userIdx: index("webauthn_credentials_user_idx").on(t.userId),
    credentialIdIdx: uniqueIndex("webauthn_credentials_credential_id_idx").on(t.credentialId),
  }),
);

export type WebauthnCredential = typeof webauthnCredentials.$inferSelect;
export type NewWebauthnCredential = typeof webauthnCredentials.$inferInsert;
