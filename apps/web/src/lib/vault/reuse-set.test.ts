import { describe, expect, it, beforeAll } from "vitest";
import { ready } from "@simplevault/crypto/browser";

import { buildReuseSet, passwordHash, reuseCountForCred } from "./reuse-set";

beforeAll(async () => {
  await ready();
});

describe("reuse-set", () => {
  it("passwordHash is deterministic + 64-hex chars (SHA-256)", () => {
    const a = passwordHash("hunter2");
    const b = passwordHash("hunter2");
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("different passwords hash to different keys", () => {
    expect(passwordHash("alpha")).not.toBe(passwordHash("beta"));
  });

  it("buildReuseSet groups credentials by password hash", () => {
    const map = buildReuseSet([
      { id: "c1", password: "shared" },
      { id: "c2", password: "shared" },
      { id: "c3", password: "unique" },
    ]);
    expect(map.size).toBe(2);
    const sharedIds = map.get(passwordHash("shared"));
    expect(sharedIds).toEqual(["c1", "c2"]);
    const uniqueIds = map.get(passwordHash("unique"));
    expect(uniqueIds).toEqual(["c3"]);
  });

  it("reuseCountForCred excludes self — unique pw → 0, reused pair → 1", () => {
    const map = buildReuseSet([
      { id: "c1", password: "shared" },
      { id: "c2", password: "shared" },
      { id: "c3", password: "unique" },
    ]);
    expect(reuseCountForCred(map, "c1", passwordHash("shared"))).toBe(1);
    expect(reuseCountForCred(map, "c2", passwordHash("shared"))).toBe(1);
    expect(reuseCountForCred(map, "c3", passwordHash("unique"))).toBe(0);
  });

  it("reuseCountForCred handles three-way reuse", () => {
    const map = buildReuseSet([
      { id: "c1", password: "p" },
      { id: "c2", password: "p" },
      { id: "c3", password: "p" },
    ]);
    expect(reuseCountForCred(map, "c1", passwordHash("p"))).toBe(2);
  });

  it("missing hash returns 0", () => {
    const map = buildReuseSet([{ id: "c1", password: "p" }]);
    expect(reuseCountForCred(map, "cX", passwordHash("never-stored"))).toBe(0);
  });
});
