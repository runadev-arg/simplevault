import { randomBytes } from "node:crypto";
import { schema } from "@simplevault/db";
import { crockfordBase32, hyphenate } from "../lib/base32.js";
import { openDb } from "../lib/db.js";
import { hmacSha256, readInviteSecret } from "../lib/hmac.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/** RFC 5321 ceiling — matches users.email/invite_codes.email varchar(254) (FINDING-0017 fold). */
const EMAIL_MAX_LEN = 254;

export interface InviteCreateOptions {
  email: string;
  ttlDays?: string;
}

/**
 * `invite create --email <addr> [--ttl-days N]` — operator-side invite issuance.
 *
 * Flow:
 *   1. raw_code = 16 random bytes → Crockford base32 (26 chars) → hyphenated
 *      every 4 chars (e.g. `K3JM-9PXQ-7T4N-22HS-VR8E-A6YF`).
 *   2. code_hash = HMAC-SHA256(SERVER_INVITE_SECRET, raw_code_bytes)
 *      — server-side pepper means a DB-only compromise can't enumerate codes.
 *   3. INSERT into invite_codes (email lowercased, expires now + ttl).
 *   4. Print the raw code to stdout ONCE; nothing else logged.
 */
export async function inviteCreate(opts: InviteCreateOptions): Promise<void> {
  const email = opts.email.trim().toLowerCase();
  if (!EMAIL_RE.test(email)) {
    process.stderr.write(`ERROR: invalid email: ${opts.email}\n`);
    process.exit(2);
  }
  if (email.length > EMAIL_MAX_LEN) {
    process.stderr.write(
      `ERROR: email exceeds ${EMAIL_MAX_LEN.toString()}-char ceiling (got ${email.length.toString()})\n`,
    );
    process.exit(2);
  }
  const ttlDays = parseTtlDays(opts.ttlDays ?? "7");
  if (ttlDays <= 0 || ttlDays > 365) {
    process.stderr.write(`ERROR: --ttl-days must be 1..365 (got ${ttlDays})\n`);
    process.exit(2);
  }

  const secret = readInviteSecret();
  const { db, pool } = openDb();

  try {
    const rawBytes = randomBytes(16);
    const code = hyphenate(crockfordBase32(rawBytes), 4);
    const codeBytes = Buffer.from(code, "utf8");
    const codeHash = hmacSha256(secret, codeBytes);

    const expiresAt = new Date(Date.now() + ttlDays * 24 * 60 * 60 * 1000);

    await db.insert(schema.inviteCodes).values({
      codeHash,
      email,
      createdBy: null,
      expiresAt,
    });

    // Single stdout emission of the raw code. No logger, no file.
    process.stdout.write(`${code}\n`);
    process.stdout.write(
      `\n(deliver this code to ${email} out-of-band — it will not be shown again)\n`,
    );
    process.stdout.write(`expires: ${expiresAt.toISOString()} (in ${ttlDays} days)\n`);
  } finally {
    await pool.end();
  }
}

function parseTtlDays(raw: string): number {
  // Accept "7" or "7d" forms.
  const m = /^(\d+)\s*d?$/i.exec(raw.trim());
  if (!m) {
    return NaN;
  }
  return Number.parseInt(m[1]!, 10);
}
