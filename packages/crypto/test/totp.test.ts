/**
 * RFC 6238 TOTP test suite.
 *
 * Vector source: RFC 6238 Appendix B "Test Vectors" using the SHA-1 column
 * (the only algorithm SimpleVault uses; mandated by the spec for
 * compatibility with the universe of TOTP authenticator apps).
 *
 * Appendix B publishes 8-digit TOTPs. SimpleVault uses 6-digit TOTPs;
 * the 6-digit value is the last 6 digits of the corresponding 8-digit
 * value (mod 10^6). Vectors below pin both forms so a future regression
 * is easy to localise.
 *
 * Shared secret (ASCII): "12345678901234567890" (20 bytes).
 */

import { beforeAll, describe, expect, it } from "vitest";

import { ready } from "../src/argon2id.js";
import {
  buildOtpauthUrl,
  computeTotpStep,
  verifyTotpCandidate,
} from "../src/totp.js";

beforeAll(async () => {
  // libsodium's HMAC-SHA-1 + memcmp bindings need the WASM ready.
  await ready();
});

const enc = new TextEncoder();
const RFC_SECRET_20B = enc.encode("12345678901234567890");

const VECTORS_8 = [
  { t: 59, step: 1, code8: "94287082", code6: "287082" },
  { t: 1111111109, step: 37037036, code8: "07081804", code6: "081804" },
  { t: 1234567890, step: 41152263, code8: "89005924", code6: "005924" },
  { t: 2000000000, step: 66666666, code8: "69279037", code6: "279037" },
] as const;

describe("computeTotpStep — RFC 6238 Appendix B (SHA-1, 6-digit)", () => {
  for (const v of VECTORS_8) {
    it(`t=${v.t.toString()} step=${v.step.toString()} produces ${v.code6}`, () => {
      const out = computeTotpStep(RFC_SECRET_20B, v.step);
      expect(out).toBe(v.code6);
    });
  }

  it("respects an explicit 8-digit width", () => {
    for (const v of VECTORS_8) {
      const out = computeTotpStep(RFC_SECRET_20B, v.step, 8);
      expect(out).toBe(v.code8);
    }
  });

  it("produces zero-padded output for low codes", () => {
    // Vector 3 is the natural "starts with 00" case in 6-digit form.
    const out = computeTotpStep(RFC_SECRET_20B, 41152263);
    expect(out.length).toBe(6);
    expect(out).toBe("005924");
  });
});

describe("verifyTotpCandidate — round-trip + drift", () => {
  it("matches the same step it computed (drift=1)", () => {
    const code = computeTotpStep(RFC_SECRET_20B, 100);
    const r = verifyTotpCandidate(RFC_SECRET_20B, code, 100, 1);
    expect(r.ok).toBe(true);
    expect(r.step).toBe(100);
  });

  it("accepts a code from step 100 when verifying at step 99 with drift=1", () => {
    const code = computeTotpStep(RFC_SECRET_20B, 100);
    const r = verifyTotpCandidate(RFC_SECRET_20B, code, 99, 1);
    expect(r.ok).toBe(true);
    expect(r.step).toBe(100);
  });

  it("accepts a code from step 100 when verifying at step 101 with drift=1", () => {
    const code = computeTotpStep(RFC_SECRET_20B, 100);
    const r = verifyTotpCandidate(RFC_SECRET_20B, code, 101, 1);
    expect(r.ok).toBe(true);
    expect(r.step).toBe(100);
  });

  it("rejects a code from step 100 when verifying at step 98 with drift=1", () => {
    const code = computeTotpStep(RFC_SECRET_20B, 100);
    const r = verifyTotpCandidate(RFC_SECRET_20B, code, 98, 1);
    expect(r.ok).toBe(false);
    expect(r.step).toBeUndefined();
  });

  it("rejects a code from step 100 when verifying at step 102 with drift=1", () => {
    const code = computeTotpStep(RFC_SECRET_20B, 100);
    const r = verifyTotpCandidate(RFC_SECRET_20B, code, 102, 1);
    expect(r.ok).toBe(false);
  });

  it("rejects a code computed under a different secret", () => {
    const otherSecret = enc.encode("00000000000000000000");
    const code = computeTotpStep(otherSecret, 100);
    const r = verifyTotpCandidate(RFC_SECRET_20B, code, 100, 1);
    expect(r.ok).toBe(false);
  });
});

describe("verifyTotpCandidate — strict format guards", () => {
  it("rejects 5-digit input", () => {
    const r = verifyTotpCandidate(RFC_SECRET_20B, "12345", 100, 1);
    expect(r.ok).toBe(false);
  });

  it("rejects 7-digit input", () => {
    const r = verifyTotpCandidate(RFC_SECRET_20B, "1234567", 100, 1);
    expect(r.ok).toBe(false);
  });

  it("rejects non-numeric input", () => {
    const r = verifyTotpCandidate(RFC_SECRET_20B, "abcdef", 100, 1);
    expect(r.ok).toBe(false);
  });

  it("rejects empty string", () => {
    const r = verifyTotpCandidate(RFC_SECRET_20B, "", 100, 1);
    expect(r.ok).toBe(false);
  });
});

describe("buildOtpauthUrl", () => {
  it("emits canonical otpauth URL with base32 secret + SHA1/6/30", () => {
    // base32(RFC 4648, no padding) of "12345678901234567890" =
    //   GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    // Pinned here to detect any regression in the inline base32 helper.
    const url = buildOtpauthUrl({
      issuer: "SimpleVault",
      account: "alice@example.com",
      secret: RFC_SECRET_20B,
    });
    expect(url.startsWith("otpauth://totp/")).toBe(true);
    // label is "SimpleVault:alice@example.com" URI-encoded
    expect(url).toContain("SimpleVault%3Aalice%40example.com");
    expect(url).toContain("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    expect(url).toContain("issuer=SimpleVault");
    expect(url).toContain("algorithm=SHA1");
    expect(url).toContain("digits=6");
    expect(url).toContain("period=30");
  });

  it("respects override period and digits", () => {
    const url = buildOtpauthUrl({
      issuer: "SV",
      account: "x@y.z",
      secret: RFC_SECRET_20B,
      period: 60,
      digits: 8,
    });
    expect(url).toContain("digits=8");
    expect(url).toContain("period=60");
  });
});

describe("totp barrel surface (browser-only invariant)", () => {
  it("is exported from the browser barrel", async () => {
    const browser = (await import("../src/browser.js")) as Record<
      string,
      unknown
    >;
    expect(typeof browser.computeTotpStep).toBe("function");
    expect(typeof browser.verifyTotpCandidate).toBe("function");
    expect(typeof browser.buildOtpauthUrl).toBe("function");
  });

  it("is NOT exported from the node barrel (server must not have access)", async () => {
    const node = (await import("../src/node.js")) as Record<string, unknown>;
    expect(node.computeTotpStep).toBeUndefined();
    expect(node.verifyTotpCandidate).toBeUndefined();
    expect(node.buildOtpauthUrl).toBeUndefined();
  });
});
