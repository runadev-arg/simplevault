import sodium from "libsodium-wrappers-sumo";
import {
  ARGON2_DEFAULT_PARAMS,
  ARGON2_FLOOR_PARAMS,
  deriveKey,
  ready,
  type Argon2Params,
} from "./argon2id.js";

/** Hard cap on memoryKiB the calibrator will return (256 MiB). */
export const ARGON2_MEMORY_CAP_KIB = 256 * 1024;

/** Max binary-search iterations before we accept the most recent reading. */
const MAX_ITER = 6;

export type CalibrationResult = {
  readonly params: Argon2Params;
  readonly measuredMs: number;
};

/**
 * Search for Argon2id params whose wall-time on this host falls within
 * [targetMs - toleranceMs, targetMs + toleranceMs]. Defaults: 750ms ± 250ms.
 *
 * Strategy: start at ARGON2_DEFAULT_PARAMS; double memoryKiB if too fast,
 * halve if too slow. Bounded by ARGON2_FLOOR_PARAMS.memoryKiB below and
 * ARGON2_MEMORY_CAP_KIB above. Iterations and parallelism are NOT tuned —
 * we leave them at defaults to keep the tuning surface 1-D.
 *
 * Operator workflow (Plan 02-06): run once on prod hardware, bake the
 * resulting params into Dokploy env vars.
 */
export async function calibrate(
  targetMs = 750,
  toleranceMs = 250,
): Promise<CalibrationResult> {
  await ready();
  const password = sodium.randombytes_buf(32);
  const salt = sodium.randombytes_buf(16);

  let memoryKiB = ARGON2_DEFAULT_PARAMS.memoryKiB;
  const iterations = ARGON2_DEFAULT_PARAMS.iterations;
  let measuredMs = 0;
  let lastParams: Argon2Params = {
    memoryKiB,
    iterations,
    parallelism: 1,
  };

  for (let i = 0; i < MAX_ITER; i++) {
    const params: Argon2Params = {
      memoryKiB,
      iterations,
      parallelism: 1,
    };
    const t0 = performance.now();
    await deriveKey(password, salt, params);
    measuredMs = performance.now() - t0;
    lastParams = params;

    if (measuredMs < targetMs - toleranceMs) {
      // too fast: more memory, unless capped.
      if (memoryKiB >= ARGON2_MEMORY_CAP_KIB) {
        break;
      }
      memoryKiB = Math.min(memoryKiB * 2, ARGON2_MEMORY_CAP_KIB);
      continue;
    }
    if (measuredMs > targetMs + toleranceMs) {
      // too slow: less memory, unless at floor.
      if (memoryKiB <= ARGON2_FLOOR_PARAMS.memoryKiB) {
        break;
      }
      memoryKiB = Math.max(
        Math.floor(memoryKiB / 2),
        ARGON2_FLOOR_PARAMS.memoryKiB,
      );
      continue;
    }
    // in band
    break;
  }

  return { params: lastParams, measuredMs };
}
