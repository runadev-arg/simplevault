/**
 * Crockford base32 encoding (no padding, uppercase) — human-friendly:
 * I/L/O/U excluded to avoid ambiguity with 1/0.
 *
 * Used by the invite-code generator: 16 random bytes → 26-char base32 → split
 * into 4-char groups joined by `-` for readability.
 */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function crockfordBase32(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

/** Group `s` every `n` characters with `-`. */
export function hyphenate(s: string, n: number): string {
  const groups: string[] = [];
  for (let i = 0; i < s.length; i += n) {
    groups.push(s.slice(i, i + n));
  }
  return groups.join("-");
}
