/**
 * Password & passphrase generator (Phase 04 / Plan 04-05).
 *
 * Entropy source: `crypto.getRandomValues` ONLY — never `Math.random`.
 * The grep-clean invariant is asserted in `generator.test.ts`.
 *
 * Uniform sampling uses rejection sampling on a Uint8Array (≤ 256-range)
 * or Uint16Array (≤ 65536-range, used for the 7776-word EFF list) to avoid
 * modulo bias.
 *
 * `generatePassword` guarantees at least one character from each enabled
 * class, then fills the remainder from the union charset and Fisher–Yates
 * shuffles so the guaranteed chars are not always at the front.
 */

import { EFF_LARGE } from "./eff-large";

export interface PasswordOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
}

export interface PassphraseOptions {
  wordCount: number;
  separator: string;
}

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "0123456789";
// 25 symbols. Total all-classes charset = 26+26+10+25 = 87.
// log2(87) ≈ 6.44; at length=20 ≈ 128.85 bits — above the 128-bit anchor.
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?";

const PASSWORD_MIN_LENGTH = 8;
const PASSWORD_MAX_LENGTH = 128;
const PASSPHRASE_MIN_WORDS = 3;
const PASSPHRASE_MAX_WORDS = 10;

/**
 * Unbiased uniform integer in [0, maxExclusive) for ranges ≤ 256.
 * Rejects values that would land in the truncated tail to eliminate modulo bias.
 */
function randInt(maxExclusive: number): number {
  if (maxExclusive <= 0 || maxExclusive > 256) {
    throw new RangeError("randInt: range out of bounds");
  }
  const buf = new Uint8Array(1);
  const limit = 256 - (256 % maxExclusive);
  for (;;) {
    crypto.getRandomValues(buf);
    // Uint8Array index is always defined; coalesce keeps the type narrow.
    const v = buf[0] ?? 0;
    if (v < limit) return v % maxExclusive;
  }
}

/**
 * Unbiased uniform integer in [0, maxExclusive) for ranges ≤ 65536.
 * Used for the 7776-entry EFF wordlist.
 */
function randIndex16(maxExclusive: number): number {
  if (maxExclusive <= 0 || maxExclusive > 65536) {
    throw new RangeError("randIndex16: range out of bounds");
  }
  const buf = new Uint16Array(1);
  const limit = 65536 - (65536 % maxExclusive);
  for (;;) {
    crypto.getRandomValues(buf);
    const v = buf[0] ?? 0;
    if (v < limit) return v % maxExclusive;
  }
}

export function generatePassword(opts: PasswordOptions): string {
  if (opts.length < PASSWORD_MIN_LENGTH || opts.length > PASSWORD_MAX_LENGTH) {
    throw new RangeError(
      `length must be ${String(PASSWORD_MIN_LENGTH)}..${String(PASSWORD_MAX_LENGTH)}`,
    );
  }
  const enabled: string[] = [];
  if (opts.lower) enabled.push(LOWER);
  if (opts.upper) enabled.push(UPPER);
  if (opts.digits) enabled.push(DIGITS);
  if (opts.symbols) enabled.push(SYMBOLS);
  if (enabled.length === 0) {
    throw new RangeError("at least one character class must be enabled");
  }
  const all = enabled.join("");

  // Pick one char from each enabled class to guarantee class invariant.
  // `String#charAt` always returns a string ("" out-of-range), satisfying
  // strict null checks without `!` non-null assertions.
  const result: string[] = enabled.map((cls) => cls.charAt(randInt(cls.length)));
  // Fill the rest from the union charset.
  while (result.length < opts.length) {
    result.push(all.charAt(randInt(all.length)));
  }
  // Fisher–Yates shuffle so the guaranteed chars aren't always at the front.
  for (let i = result.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    const ri = result[i] ?? "";
    const rj = result[j] ?? "";
    result[i] = rj;
    result[j] = ri;
  }
  return result.join("");
}

export function generatePassphrase(opts: PassphraseOptions): string {
  if (
    opts.wordCount < PASSPHRASE_MIN_WORDS ||
    opts.wordCount > PASSPHRASE_MAX_WORDS
  ) {
    throw new RangeError(
      `wordCount must be ${String(PASSPHRASE_MIN_WORDS)}..${String(PASSPHRASE_MAX_WORDS)}`,
    );
  }
  const words: string[] = [];
  for (let i = 0; i < opts.wordCount; i++) {
    const word = EFF_LARGE[randIndex16(EFF_LARGE.length)] ?? "";
    words.push(word);
  }
  return words.join(opts.separator);
}
