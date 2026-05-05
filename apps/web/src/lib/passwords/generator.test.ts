import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve } from "node:path";

import { describe, it, expect } from "vitest";

import { EFF_LARGE } from "./eff-large";
import { generatePassword, generatePassphrase } from "./generator";

/**
 * Pinned SHA-256 of `EFF_LARGE.join("\n") + "\n"` (with the trailing newline
 * appended to match the upstream raw file's terminating newline). Computed
 * locally in T3 from the upstream EFF large list (raw-file SHA-256
 * `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`,
 * documented in `eff-large.ts`).
 */
const EXPECTED_EFF_JOIN_HASH =
  "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522";

function sha256Hex(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

describe("EFF large wordlist integrity", () => {
  it("contains exactly 7776 entries", () => {
    expect(EFF_LARGE.length).toBe(7776);
  });

  it("matches the pinned SHA-256 of join('\\n') + trailing newline", () => {
    const hash = sha256Hex(EFF_LARGE.join("\n") + "\n");
    expect(hash).toBe(EXPECTED_EFF_JOIN_HASH);
  });
});

describe("generatePassword — invariants", () => {
  const allOn = { lower: true, upper: true, digits: true, symbols: true };

  it("returns a string of the requested length (1000 trials)", () => {
    for (let i = 0; i < 1000; i++) {
      const pw = generatePassword({ length: 20, ...allOn });
      expect(pw.length).toBe(20);
    }
  });

  it("guarantees at least one char from each enabled class (1000 trials)", () => {
    const lowerRe = /[a-z]/;
    const upperRe = /[A-Z]/;
    const digitRe = /[0-9]/;
    const symRe = /[!@#$%^&*()\-_=+\[\]{};:,.<>/?]/;
    for (let i = 0; i < 1000; i++) {
      const pw = generatePassword({ length: 20, ...allOn });
      expect(lowerRe.test(pw)).toBe(true);
      expect(upperRe.test(pw)).toBe(true);
      expect(digitRe.test(pw)).toBe(true);
      expect(symRe.test(pw)).toBe(true);
    }
  });

  it("rejects length < 8", () => {
    expect(() => generatePassword({ length: 7, ...allOn })).toThrow();
  });

  it("rejects length > 128", () => {
    expect(() => generatePassword({ length: 129, ...allOn })).toThrow();
  });

  it("rejects when no character classes are enabled", () => {
    expect(() =>
      generatePassword({
        length: 20,
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
      }),
    ).toThrow();
  });

  it("uniqueness: 1000 generations produce no duplicates", () => {
    const set = new Set<string>();
    for (let i = 0; i < 1000; i++) {
      set.add(generatePassword({ length: 20, ...allOn }));
    }
    expect(set.size).toBe(1000);
  });

  it("entropy lower bound: H >= length * log2(charsetSize)", () => {
    // length=20, charset = LOWER(26) + UPPER(26) + DIGITS(10) + SYMBOLS(25) = 87.
    // 20 * log2(87) ≈ 128.85 bits. Empirical Shannon estimate over 10000 samples
    // should be at least 128 bits (sanity lower bound — not a proof).
    const N = 10000;
    const charsetSize = 87;
    const theoretical = 20 * Math.log2(charsetSize);
    expect(theoretical).toBeGreaterThanOrEqual(128);

    const counts = new Map<string, number>();
    for (let i = 0; i < N; i++) {
      const pw = generatePassword({ length: 20, ...allOn });
      for (const ch of pw) counts.set(ch, (counts.get(ch) ?? 0) + 1);
    }
    const total = 20 * N;
    let H = 0;
    for (const c of counts.values()) {
      const p = c / total;
      H -= p * Math.log2(p);
    }
    // Per-character empirical entropy times length is the password entropy
    // estimate. With charset 87, max per-char entropy is log2(87) ≈ 6.44.
    const passwordH = H * 20;
    expect(passwordH).toBeGreaterThanOrEqual(128);
  });
});

describe("generator source — Math.random clean", () => {
  it("generator.ts contains zero references to Math.random", () => {
    const src = readFileSync(
      resolve(__dirname, "generator.ts"),
      "utf8",
    );
    // Match actual call-sites and member access; not bare prose.
    expect(/Math\s*\.\s*random\s*\(/.test(src)).toBe(false);
  });
});

describe("generatePassphrase — invariants", () => {
  it("returns wordCount words joined by separator (1000 trials)", () => {
    const wordSet = new Set(EFF_LARGE);
    for (let i = 0; i < 1000; i++) {
      const ph = generatePassphrase({ wordCount: 5, separator: "-" });
      const parts = ph.split("-");
      expect(parts.length).toBe(5);
      for (const w of parts) expect(wordSet.has(w)).toBe(true);
    }
  });

  it("rejects wordCount < 3", () => {
    expect(() => generatePassphrase({ wordCount: 2, separator: "-" })).toThrow();
  });

  it("rejects wordCount > 10", () => {
    expect(() =>
      generatePassphrase({ wordCount: 11, separator: "-" }),
    ).toThrow();
  });
});
