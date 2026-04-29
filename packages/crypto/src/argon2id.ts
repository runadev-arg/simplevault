import sodium from "libsodium-wrappers-sumo";

/**
 * Argon2id parameter shape used across SimpleVault.
 * `parallelism` is literal-typed to 1 because libsodium-wrappers is single-threaded WASM.
 */
export type Argon2Params = {
  readonly memoryKiB: number;
  readonly iterations: number;
  readonly parallelism: 1;
};

/**
 * SimpleVault default Argon2id params (CRYPTO-STACK.md): m=64MiB, t=3, p=1.
 * Plan 02-06 ships a CLI to calibrate per-host and bake measured params into env.
 */
export const ARGON2_DEFAULT_PARAMS: Argon2Params = Object.freeze({
  memoryKiB: 64 * 1024,
  iterations: 3,
  parallelism: 1,
});

/**
 * Conservative floor: OWASP 2023 minimum for Argon2id (m=19MiB, t=2, p=1).
 * Calibrate() must never return params weaker than this.
 */
export const ARGON2_FLOOR_PARAMS: Argon2Params = Object.freeze({
  memoryKiB: 19 * 1024,
  iterations: 2,
  parallelism: 1,
});

const SALT_BYTES_MIN = 16; // libsodium crypto_pwhash_SALTBYTES

let _ready: Promise<void> | null = null;
/**
 * Memoised libsodium init. Safe to call from multiple call sites concurrently.
 */
export async function ready(): Promise<void> {
  if (_ready === null) {
    _ready = sodium.ready;
  }
  return _ready;
}

/**
 * Translate human-readable Argon2 params to libsodium opslimit/memlimit pair.
 * - opslimit ≡ iterations
 * - memlimit ≡ memoryKiB * 1024 (bytes)
 */
export function paramsToOpsMem(params: Argon2Params): {
  opslimit: number;
  memlimit: number;
} {
  return {
    opslimit: params.iterations,
    memlimit: params.memoryKiB * 1024,
  };
}

export class Argon2SaltTooShortError extends Error {
  constructor(actual: number) {
    super(
      `argon2id: salt must be >= ${SALT_BYTES_MIN} bytes (got ${actual})`,
    );
    this.name = "Argon2SaltTooShortError";
  }
}

/**
 * Derive a key from a password+salt under Argon2id.
 * @returns a `outLen`-byte Uint8Array (default 32).
 */
export async function deriveKey(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params,
  outLen = 32,
): Promise<Uint8Array> {
  await ready();
  if (salt.length < SALT_BYTES_MIN) {
    throw new Argon2SaltTooShortError(salt.length);
  }
  const { opslimit, memlimit } = paramsToOpsMem(params);
  return sodium.crypto_pwhash(
    outLen,
    password,
    salt,
    opslimit,
    memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

/**
 * Constant-time verify: re-derive the key and compare against `expectedKey` via sodium.memcmp.
 */
export async function verify(
  password: Uint8Array,
  salt: Uint8Array,
  params: Argon2Params,
  expectedKey: Uint8Array,
): Promise<boolean> {
  await ready();
  const actual = await deriveKey(password, salt, params, expectedKey.length);
  return sodium.memcmp(actual, expectedKey);
}
