import { createHmac } from "node:crypto";

/**
 * HMAC-SHA256 of `data` keyed with `SERVER_INVITE_SECRET`.
 *
 * The CLI stores HMAC(secret, raw_code) in `invite_codes.code_hash` so a
 * DB-only compromise cannot enumerate raw codes (the secret is a server-side
 * pepper held only in env / Dokploy secrets).
 */
export function hmacSha256(secret: Buffer, data: Buffer): Buffer {
  const h = createHmac("sha256", secret);
  h.update(data);
  return h.digest();
}

/**
 * Read + validate `SERVER_INVITE_SECRET` from process.env.
 * Fails fast (process.exit(2)) if missing or shorter than 32 bytes once
 * decoded. Accepts base64, base64url, or hex; falls back to UTF-8 raw bytes.
 */
export function readInviteSecret(): Buffer {
  const raw = process.env["SERVER_INVITE_SECRET"];
  if (!raw || raw.length === 0) {
    process.stderr.write(
      "ERROR: SERVER_INVITE_SECRET is not set. Generate with `openssl rand -base64 32`.\n",
    );
    process.exit(2);
  }
  // Try base64 first, then hex, then UTF-8.
  const candidates: Buffer[] = [];
  try {
    candidates.push(Buffer.from(raw, "base64"));
  } catch {
    /* ignore */
  }
  if (/^[0-9a-fA-F]+$/.test(raw) && raw.length % 2 === 0) {
    candidates.push(Buffer.from(raw, "hex"));
  }
  candidates.push(Buffer.from(raw, "utf8"));
  // Pick the longest decoding that is >= 32 bytes; otherwise utf8.
  const ok = candidates.find((b) => b.length >= 32);
  if (!ok) {
    process.stderr.write(
      "ERROR: SERVER_INVITE_SECRET decodes to fewer than 32 bytes. Use `openssl rand -base64 32`.\n",
    );
    process.exit(2);
  }
  return ok;
}
