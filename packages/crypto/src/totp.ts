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

// Stubs — replaced with the real implementation in Task 2 (GREEN).

/**
 * Compute the RFC 6238 TOTP code for `secret` at the given step.
 *
 * `step = floor(unixSeconds / 30)`. Returns a zero-padded numeric string of
 * length `digits` (default 6). HMAC-SHA-1 + RFC 4226 §5.3 dynamic truncation.
 */
export function computeTotpStep(
  _secret: Uint8Array,
  _step: number,
  _digits = 6,
): string {
  throw new Error("totp.computeTotpStep: not implemented");
}

/**
 * Verify a candidate code against `secret`, accepting drift in the
 * range `[currentStep - drift, currentStep + drift]`. Returns the
 * matched step on success.
 */
export function verifyTotpCandidate(
  _secret: Uint8Array,
  _code: string,
  _currentStep: number,
  _drift = 1,
): { ok: boolean; step?: number } {
  throw new Error("totp.verifyTotpCandidate: not implemented");
}

/**
 * Build an `otpauth://totp/...` provisioning URL for QR display. Output is
 * canonical: secret base32 (RFC 4648, no padding), algorithm SHA1, digits 6,
 * period 30 unless overridden.
 */
export function buildOtpauthUrl(_opts: {
  issuer: string;
  account: string;
  secret: Uint8Array;
  period?: number;
  digits?: number;
}): string {
  throw new Error("totp.buildOtpauthUrl: not implemented");
}
