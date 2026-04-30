/**
 * Crockford-base32 encode/decode for the 16-byte secret_key.
 *
 * Encoder: extracted from `apps/web/src/app/signup/steps/SecretKeyRevealStep.tsx`
 * (per the 02-10 hand-off: "move to a shared module if 02-11 needs it").
 * The login flow needs the inverse to parse user input back into bytes.
 */

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function bytesToCrockford(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      const ch = CROCKFORD[(value >>> bits) & 0x1f];
      out += ch ?? "";
    }
  }
  if (bits > 0) {
    const ch = CROCKFORD[(value << (5 - bits)) & 0x1f];
    out += ch ?? "";
  }
  return out.match(/.{1,4}/g)?.join("-") ?? out;
}

/**
 * Normalise user-typed input: upper-case, drop hyphens/spaces, then map
 * Crockford's confusable characters (`O`->`0`, `I/L`->`1`) and strip
 * anything outside the alphabet.
 */
export function normaliseCrockford(s: string): string {
  return s
    .toUpperCase()
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1")
    .replace(/[^0-9A-Z]/g, "");
}

export class SecretKeyFormatError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "SecretKeyFormatError";
  }
}

/**
 * Decode 26 Crockford-base32 chars (= 130 bits, of which the trailing 2
 * bits are zero-padding) into a 16-byte Uint8Array. Throws on bad chars
 * or unexpected length.
 */
export function crockfordToBytes(s: string): Uint8Array {
  const norm = normaliseCrockford(s);
  if (norm.length !== 26) {
    throw new SecretKeyFormatError(
      `Secret key must be 26 base32 characters (got ${norm.length} after normalisation).`,
    );
  }
  let bits = 0;
  let value = 0;
  const out = new Uint8Array(16);
  let pos = 0;
  for (const ch of norm) {
    const idx = CROCKFORD.indexOf(ch);
    if (idx < 0) {
      throw new SecretKeyFormatError(`Illegal character '${ch}' in secret key.`);
    }
    value = (value << 5) | idx;
    bits += 5;
    while (bits >= 8 && pos < 16) {
      bits -= 8;
      out[pos++] = (value >>> bits) & 0xff;
    }
  }
  if (pos !== 16) {
    throw new SecretKeyFormatError("Secret key did not decode to 16 bytes.");
  }
  return out;
}
