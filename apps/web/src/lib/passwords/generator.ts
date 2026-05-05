/**
 * Password & passphrase generator (Phase 04 / Plan 04-05).
 *
 * Stub for T1 (RED). Real implementation arrives in T2 (GREEN).
 *
 * Entropy source MUST be `crypto.getRandomValues` only — never `Math.random`.
 * The grep-clean invariant is asserted in `generator.test.ts`.
 */

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

export function generatePassword(_opts: PasswordOptions): string {
  throw new Error("not impl");
}

export function generatePassphrase(_opts: PassphraseOptions): string {
  throw new Error("not impl");
}
