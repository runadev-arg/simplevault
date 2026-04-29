import { createHash, timingSafeEqual } from "node:crypto";

/**
 * Timing-floor utility for /auth/login.
 *
 * The login service must execute the same constant-time comparison work
 * regardless of whether the email exists. When the user row is absent we
 * substitute this DUMMY_HASH so the wall-time of the user-not-found path is
 * indistinguishable (within DB-lookup jitter) from the wrong-password path.
 *
 * DUMMY_HASH is derived deterministically from `JWT_SECRET` so an attacker
 * probing for a fixed value can't simply compare against a published constant
 * — yet it stays stable across restarts on the same deployment so the
 * comparison is repeatable. We never compare candidate hashes for equality
 * with DUMMY_HASH; the result is intentionally always `false` because the
 * client could not have produced this exact 32-byte sequence.
 *
 * This is per server-side timing-floor (the heavy Argon2id work happens on
 * the client; the server's only secret-touching primitive is constant-time
 * memcmp of two 32-byte buffers, which is what we equalise here).
 */

let _dummy: Buffer | null = null;

export function dummyHash(): Buffer {
  if (_dummy) return _dummy;
  const secret = process.env.JWT_SECRET ?? "";
  // 32-byte deterministic value derived from JWT_SECRET so an external
  // attacker can't predict it. If JWT_SECRET is unset the api fails fast at
  // boot via JwtService — but during early imports we still need a non-null
  // fallback; sha256 of empty string is fine in that degenerate case.
  _dummy = createHash("sha256").update("sv:dummy-verifier:v1|").update(secret).digest();
  return _dummy;
}

/**
 * Constant-time compare against a 32-byte verifier. Always runs the timing
 * primitive even when `verifier` is null — call sites pass `dummyHash()` in
 * that case.
 */
export function constantTimeEqual32(candidate: Buffer, verifier: Buffer): boolean {
  if (candidate.length !== 32 || verifier.length !== 32) return false;
  return timingSafeEqual(candidate, verifier);
}
