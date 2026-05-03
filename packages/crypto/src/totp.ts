/**
 * RFC 6238 TOTP — browser-only.
 *
 * SECURITY INVARIANT (LOAD-BEARING — Phase 03 Key Link 3):
 *
 * This module is exported ONLY from `./browser.ts`. It is intentionally
 * absent from `./node.ts` (and from the symbol-parity snapshot in
 * `test/parity.test.ts`). The TOTP secret is browser-only — the API server
 * stores ONLY the wrapped blob + AAD bytes and runs ZERO RFC 6238
 * arithmetic. Server code that accidentally `import`s this module from
 * `@simplevault/crypto/node` will fail to compile.
 *
 * SHA-1 caveat: RFC 6238 + RFC 4226 mandate HMAC-SHA-1 for compatibility
 * with every TOTP authenticator in the wild (Google Authenticator,
 * 1Password, Aegis, Authy, …). This is the ONLY SHA-1 use in SimpleVault.
 * Do NOT propagate; do NOT generalise this helper.
 */

import { hmac } from "@noble/hashes/hmac";
import { sha1 } from "@noble/hashes/sha1";
import sodium from "libsodium-wrappers-sumo";

import { ready } from "./argon2id.js";

/**
 * HMAC-SHA-1 backend choice: `@noble/hashes` (already a dependency).
 *
 * libsodium-wrappers-sumo does NOT expose `crypto_auth_hmacsha1` — sumo
 * ships SHA-256 and SHA-512 HMAC bindings but explicitly drops SHA-1
 * (libsodium itself has the primitive but the JS wrapper omits it as
 * "deprecated"). Switching the entire vault to noble for HMAC would be
 * a wider change; for THIS one RFC-mandated SHA-1 use we pull it from
 * noble. noble is pure JS, browser-safe, audited (Cure53 2024).
 *
 * The `sodium.memcmp` constant-time compare in `verifyTotpCandidate`
 * still uses libsodium because we want a single CT-compare primitive
 * project-wide (matches `aead.decrypt`'s tag-mismatch handling).
 */

/**
 * Compute the RFC 6238 TOTP code for `secret` at the given step.
 *
 * `step = floor(unixSeconds / 30)`. Returns a zero-padded numeric string of
 * length `digits` (default 6).
 *
 * Pipeline (RFC 4226 §5.3 + RFC 6238 §4):
 *   1. Encode `step` as 8-byte big-endian.
 *   2. HMAC-SHA-1(key=secret, msg=stepBytes) -> 20 bytes.
 *   3. Dynamic truncation: offset = mac[19] & 0x0f; take 4 bytes starting
 *      at `offset`, mask high bit, big-endian -> 31-bit unsigned int.
 *   4. value mod 10^digits, zero-pad on the left.
 */
export function computeTotpStep(
  secret: Uint8Array,
  step: number,
  digits = 6,
): string {
  if (!Number.isFinite(step) || step < 0) {
    throw new RangeError(`totp: step must be a non-negative integer (got ${step.toString()})`);
  }
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new RangeError(`totp: digits must be in [6, 10] (got ${digits.toString()})`);
  }

  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(step), false);

  const mac = hmac(sha1, secret, buf); // 20 bytes
  if (mac.length !== 20) {
    throw new Error(`totp: HMAC-SHA-1 returned ${mac.length.toString()} bytes (expected 20)`);
  }

  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const b0 = (mac[offset] ?? 0) & 0x7f;
  const b1 = (mac[offset + 1] ?? 0) & 0xff;
  const b2 = (mac[offset + 2] ?? 0) & 0xff;
  const b3 = (mac[offset + 3] ?? 0) & 0xff;
  const code = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;

  const mod = 10 ** digits;
  return (code % mod).toString().padStart(digits, "0");
}

/**
 * Verify a candidate code against `secret`, accepting drift in the range
 * `[currentStep - drift, currentStep + drift]`. Returns the matched step
 * on success.
 *
 * Strict format guard: only `/^\d{6}$/` is accepted. 7+ digit codes are
 * rejected even if the leading digits would match — callers wanting wider
 * widths must be explicit at the API boundary.
 *
 * Constant-time across the drift window: every candidate is compared via
 * libsodium's `memcmp`, and we ALWAYS scan all `2*drift + 1` slots before
 * returning to avoid leaking the matched slot via timing.
 */
export function verifyTotpCandidate(
  secret: Uint8Array,
  code: string,
  currentStep: number,
  drift = 1,
): { ok: boolean; step?: number } {
  if (!/^\d{6}$/.test(code)) {
    return { ok: false };
  }
  const enc = new TextEncoder();
  const candidate = enc.encode(code);

  let matchedStep = -1;
  for (let d = -drift; d <= drift; d++) {
    const step = currentStep + d;
    if (step < 0) continue;
    const computed = enc.encode(computeTotpStep(secret, step));
    // memcmp returns true on equality; we walk the full window even after a
    // hit to keep timing constant.
    if (sodium.memcmp(computed, candidate) && matchedStep === -1) {
      matchedStep = step;
    }
  }
  return matchedStep === -1 ? { ok: false } : { ok: true, step: matchedStep };
}

/**
 * Build an `otpauth://totp/...` provisioning URL for QR display. Output is
 * canonical: secret base32 (RFC 4648, no padding), algorithm SHA1, digits 6,
 * period 30 unless overridden.
 */
export function buildOtpauthUrl(opts: {
  issuer: string;
  account: string;
  secret: Uint8Array;
  period?: number;
  digits?: number;
}): string {
  const period = opts.period ?? 30;
  const digits = opts.digits ?? 6;
  const b32 = base32encode(opts.secret);
  const label = encodeURIComponent(`${opts.issuer}:${opts.account}`);
  const params = new URLSearchParams({
    secret: b32,
    issuer: opts.issuer,
    algorithm: "SHA1",
    digits: digits.toString(),
    period: period.toString(),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Module-level readiness for libsodium's WASM (the HMAC-SHA-1 + memcmp
 * primitives this file uses). Re-exported callers that hit `computeTotpStep`
 * synchronously must await this once at app boot.
 */
export async function totpReady(): Promise<void> {
  await ready();
}

// ---------------------------------------------------------------------------
// RFC 4648 base32 (no padding) — inline to avoid pulling in a dependency.

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | (bytes[i] ?? 0);
    bits += 8;
    while (bits >= 5) {
      const idx = (value >>> (bits - 5)) & 0x1f;
      out += B32_ALPHABET[idx];
      bits -= 5;
    }
  }
  if (bits > 0) {
    const idx = (value << (5 - bits)) & 0x1f;
    out += B32_ALPHABET[idx];
  }
  return out;
}
