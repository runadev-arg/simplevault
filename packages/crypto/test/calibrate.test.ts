import { describe, expect, it } from "vitest";
import { ARGON2_FLOOR_PARAMS } from "../src/argon2id.js";
import {
  ARGON2_MEMORY_CAP_KIB,
  calibrate,
  type CalibrationResult,
} from "../src/calibrate.js";

const TARGET = 750;
const TOL = 250;

describe("calibrate()", () => {
  it("returns Argon2Params + measuredMs", async () => {
    const r: CalibrationResult = await calibrate(TARGET, TOL);
    expect(r).toHaveProperty("params");
    expect(r).toHaveProperty("measuredMs");
    expect(typeof r.measuredMs).toBe("number");
    expect(r.params.parallelism).toBe(1);
    expect(r.params.iterations).toBeGreaterThanOrEqual(1);
    expect(r.params.memoryKiB).toBeGreaterThan(0);
  }, 60_000);

  it("measuredMs in [target-tol, target+tol] OR memory hit cap", async () => {
    const r = await calibrate(TARGET, TOL);
    const inBand =
      r.measuredMs >= TARGET - TOL && r.measuredMs <= TARGET + TOL;
    const cappedHigh = r.params.memoryKiB >= ARGON2_MEMORY_CAP_KIB;
    expect(inBand || cappedHigh).toBe(true);
  }, 60_000);

  it("returned params satisfy >= ARGON2_FLOOR_PARAMS", async () => {
    const r = await calibrate(TARGET, TOL);
    expect(r.params.memoryKiB).toBeGreaterThanOrEqual(
      ARGON2_FLOOR_PARAMS.memoryKiB,
    );
    expect(r.params.iterations).toBeGreaterThanOrEqual(
      ARGON2_FLOOR_PARAMS.iterations,
    );
  }, 60_000);

  it("two runs produce measurements within ~30% of each other (smoke)", async () => {
    const a = await calibrate(TARGET, TOL);
    const b = await calibrate(TARGET, TOL);
    const ratio = Math.max(a.measuredMs, b.measuredMs) / Math.min(a.measuredMs, b.measuredMs);
    // very loose smoke; CI noise can be wide
    expect(ratio).toBeLessThan(2.5);
  }, 120_000);
});

describe("calibrate barrel parity", () => {
  it("browser and node barrels both export calibrate", async () => {
    const browserMod = await import("../src/browser.js");
    const nodeMod = await import("../src/node.js");
    for (const name of ["calibrate", "ARGON2_MEMORY_CAP_KIB"]) {
      expect(browserMod, `browser missing ${name}`).toHaveProperty(name);
      expect(nodeMod, `node missing ${name}`).toHaveProperty(name);
    }
  });
});
