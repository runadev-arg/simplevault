import { customType } from "drizzle-orm/pg-core";

/**
 * Postgres `bytea` mapped to/from `Uint8Array` on the JS side.
 *
 * Centralised here so every schema file uses an identical custom type
 * (avoids subtle drift between modules and keeps Drizzle Kit's snapshot
 * consistent across regenerations).
 */
export const bytea = customType<{ data: Uint8Array; driverData: Buffer }>({
  dataType: () => "bytea",
  toDriver: (v) => Buffer.from(v),
  fromDriver: (v) => new Uint8Array(v as Buffer),
});
