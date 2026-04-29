import {
  ARGON2_FLOOR_PARAMS,
  ARGON2_MEMORY_CAP_KIB,
  calibrate,
} from "@simplevault/crypto/node";

/**
 * `argon2 calibrate` — run the calibrator on this host and print:
 *   - measured wall-time
 *   - recommended Argon2id params
 *   - a Dokploy-paste-ready env-var snippet
 *
 * Operator runs this ONCE on the production VPS before going live, then
 * sets ARGON2_MEMORY_KIB / ARGON2_ITERATIONS / ARGON2_PARALLELISM in
 * Dokploy's encrypted env-var UI.
 *
 * Warns if the discovered params land at or below the conservative floor
 * (m=19456, t=2, p=1) — that means the host is too underpowered for prod
 * and the operator should pick beefier hardware.
 */
export async function argon2Calibrate(): Promise<void> {
  process.stdout.write("Running Argon2id calibration (target ~750ms)…\n");
  const { params, measuredMs } = await calibrate(750, 250);

  process.stdout.write(`\nMeasured: ${measuredMs.toFixed(1)} ms\n`);
  process.stdout.write(
    `Params:   memoryKiB=${params.memoryKiB} iterations=${params.iterations} parallelism=${params.parallelism}\n`,
  );

  process.stdout.write("\n--- Dokploy env-var snippet (copy/paste) ---\n");
  process.stdout.write(`ARGON2_MEMORY_KIB=${params.memoryKiB}\n`);
  process.stdout.write(`ARGON2_ITERATIONS=${params.iterations}\n`);
  process.stdout.write(`ARGON2_PARALLELISM=${params.parallelism}\n`);
  process.stdout.write("--------------------------------------------\n");

  if (
    params.memoryKiB <= ARGON2_FLOOR_PARAMS.memoryKiB ||
    params.iterations < ARGON2_FLOOR_PARAMS.iterations
  ) {
    process.stdout.write(
      "\nWARNING: discovered params are at or below the conservative floor " +
        `(m=${ARGON2_FLOOR_PARAMS.memoryKiB}, t=${ARGON2_FLOOR_PARAMS.iterations}, p=${ARGON2_FLOOR_PARAMS.parallelism}).\n` +
        "This host is likely too underpowered for production. Consider beefier hardware.\n",
    );
  }
  if (params.memoryKiB >= ARGON2_MEMORY_CAP_KIB) {
    process.stdout.write(
      "\nNOTE: calibrator hit the memory cap " +
        `(${ARGON2_MEMORY_CAP_KIB} KiB). Hardware is faster than the target; ` +
        "params accept the cap. You may raise the cap in @simplevault/crypto " +
        "if you want a longer KDF wall-time.\n",
    );
  }
}
