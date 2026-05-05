import sodium from "libsodium-wrappers-sumo";

/**
 * Phase 04 / Plan 06 — base64url boundary helpers for the credentials wire
 * shape. The Plan-04-06 contract is that ciphertext / nonce travel as
 * base64url-encoded strings (URL-safe alphabet, no padding) over JSON, and
 * land back as `Uint8Array` on the JS side.
 *
 * Implementation defers to libsodium-wrappers-sumo (already a hard dep
 * across signup-derivations, totp-wrap, login-derivations) so we do not
 * introduce a second base64 implementation. `sodium.ready` MUST be awaited
 * before either helper is invoked — every consumer of credentials-client.ts
 * already awaits it in the surrounding crypto pipeline (see
 * `credential-cipher.ts`).
 */

export function bytesToB64Url(b: Uint8Array): string {
  return sodium.to_base64(b, sodium.base64_variants.URLSAFE_NO_PADDING);
}

export function b64UrlToBytes(s: string): Uint8Array {
  return sodium.from_base64(s, sodium.base64_variants.URLSAFE_NO_PADDING);
}
