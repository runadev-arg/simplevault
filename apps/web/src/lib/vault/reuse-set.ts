/**
 * Phase 04 / Plan 04-09 — browser-side password-reuse detection.
 *
 * Maintains a `Map<sha256(password), credentialId[]>` over all decrypted
 * credentials in the current vault. Cards consult the map to render a
 * `<ReuseBadge>` when their plaintext password collides with another
 * credential's.
 *
 * INVARIANTS (LOAD-BEARING — INDEX Truth 8):
 *   - All hashing + Set bookkeeping happens IN THE BROWSER. The server
 *     NEVER sees plaintext passwords nor their SHA-256 hashes. The
 *     verify-grep step in Plan 04-12 enforces this with
 *     `grep -rn 'sha256\|reuse' apps/api/src/credentials apps/api/src/vault`
 *     returning ZERO.
 *   - The Map keys the SHA-256 hash (hex-encoded) — NOT the plaintext —
 *     so React state never holds plaintext passwords long-term. The
 *     caller's bulk-decrypt array `{id, password}` MUST go out of scope
 *     immediately after `buildReuseSet` consumes it.
 *
 * libsodium readiness: `sodium.crypto_hash_sha256` requires the WASM
 * runtime to be initialised. Callers MUST `await ready()` from
 * `@simplevault/crypto/browser` before invoking `passwordHash`.
 */

import sodium from "libsodium-wrappers-sumo";

/** SHA-256 hex of a password — Set membership key. Not a credential. */
export function passwordHash(pw: string): string {
  return sodium.to_hex(sodium.crypto_hash_sha256(sodium.from_string(pw)));
}

/**
 * Build the reuse-Map. Returns `Map<sha256-hex, credentialId[]>`. A
 * password is "reused" iff its hash key has length >= 2.
 */
export function buildReuseSet(
  decryptedCreds: readonly { id: string; password: string }[],
): Map<string, string[]> {
  const m = new Map<string, string[]>();
  for (const c of decryptedCreds) {
    const h = passwordHash(c.password);
    const arr = m.get(h);
    if (arr === undefined) {
      m.set(h, [c.id]);
    } else {
      arr.push(c.id);
    }
  }
  return m;
}

/**
 * Reuse count for a single credential, EXCLUDING self. `0` means the
 * password is unique in this vault. `>=1` means at least one other
 * credential shares it.
 */
export function reuseCountForCred(
  map: Map<string, string[]>,
  credId: string,
  pwHash: string,
): number {
  const ids = map.get(pwHash);
  if (ids === undefined) return 0;
  // Subtract self if present (it should be — caller fed us this cred).
  const selfPresent = ids.includes(credId) ? 1 : 0;
  return Math.max(0, ids.length - selfPresent);
}
