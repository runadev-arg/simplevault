import * as bip39 from "bip39";
import sodium from "libsodium-wrappers-sumo";
import { sha256 } from "@noble/hashes/sha256";
import { ready } from "./argon2id.js";

/**
 * BIP-39 24-word recovery flow for SimpleVault.
 *
 * Browser-bundle hygiene: this module imports `bip39` (works in browser via
 * its bundled `pbkdf2`/`randombytes` shims), `@noble/hashes` (pure JS), and
 * `libsodium-wrappers-sumo` for entropy. NO `node:crypto` / `node:buffer`.
 *
 * Entropy source: libsodium's `randombytes_buf` (via `bip39.entropyToMnemonic`)
 * NOT `bip39.generateMnemonic()`'s default — that pulls `crypto.randomBytes`
 * which breaks browser parity unless polyfilled.
 *
 * Server-side invariant: server NEVER sees the mnemonic. Server only stores
 * `recovery_hmac = HMAC(server_secret, sha256(canonical(mnemonic)))`. The
 * inner sha256 is what `computeRecoveryLookupHash` exposes here; the API
 * layer applies the outer HMAC at usage site.
 */

const ENTROPY_BITS = 256; // 24 words = 256 bits + 8-bit checksum
const ENTROPY_BYTES = ENTROPY_BITS / 8;

/**
 * Generate a fresh 24-word English BIP-39 mnemonic backed by libsodium entropy
 * (browser-parity-safe). Caller MUST display this once and never persist it
 * server-side.
 */
export function generateMnemonic(): string {
  // libsodium must be initialised before randombytes_buf works.
  // We expect ready() to have been awaited at least once at app boot;
  // sodium.randombytes_buf is sync once the WASM is loaded.
  const entropy = sodium.randombytes_buf(ENTROPY_BYTES);
  // bip39.entropyToMnemonic accepts hex string OR Buffer. Pass hex for
  // cross-runtime safety (no Buffer dependency in browser bundle).
  const hex = bytesToHex(entropy);
  return bip39.entropyToMnemonic(hex);
}

/**
 * Async sibling of `generateMnemonic` — call this from boot paths that
 * haven't yet awaited `ready()`. Otherwise prefer the sync version.
 */
export async function generateMnemonicAsync(): Promise<string> {
  await ready();
  return generateMnemonic();
}

/**
 * Validate a candidate mnemonic against the English wordlist + checksum.
 * Returns false for any defect (bad word, bad checksum, wrong word count).
 */
export function validateMnemonic(mnemonic: string): boolean {
  return bip39.validateMnemonic(mnemonic);
}

/**
 * Derive the 64-byte BIP-39 seed from `(mnemonic, passphrase)` per the spec
 * (PBKDF2-HMAC-SHA512, 2048 rounds, salt = "mnemonic" + passphrase).
 *
 * Returns a plain `Uint8Array` (not Node Buffer) for cross-runtime parity.
 */
export async function mnemonicToSeed(
  mnemonic: string,
  passphrase = "",
): Promise<Uint8Array> {
  const buf = await bip39.mnemonicToSeed(mnemonic, passphrase);
  // Buffer extends Uint8Array; copy the bytes into a plain Uint8Array view
  // so callers (and tests) get a stable cross-runtime shape.
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength).slice();
}

/**
 * Canonicalise a mnemonic for *lookup-hash* equality:
 *   1. Unicode NFKD normalisation
 *   2. lowercase
 *   3. trim + collapse internal whitespace runs to a single ASCII space
 *
 * NOTE: this is for the SERVER-LOOKUP HMAC INPUT only. The actual seed
 * derivation in `mnemonicToSeed` follows the BIP-39 spec (which itself
 * normalises NFKD internally) and MUST NOT be replaced with this output.
 */
function canonicaliseMnemonic(mnemonic: string): string {
  return mnemonic
    .normalize("NFKD")
    .toLowerCase()
    .trim()
    .split(/\s+/u)
    .join(" ");
}

/**
 * Compute the *inner* recovery lookup hash:
 *   sha256(utf8(canonicalise(mnemonic)))
 *
 * The API layer composes the *outer*, server-secret-bound HMAC at use site:
 *   recovery_hmac = HMAC-SHA256(SERVER_RECOVERY_HMAC_SECRET, this_value)
 *
 * Splitting the two-step keeps the server secret out of the crypto package
 * (and out of the browser bundle) while letting the client supply only an
 * unkeyed digest of its phrase to the API.
 */
export function computeRecoveryLookupHash(mnemonic: string): Uint8Array {
  const canonical = canonicaliseMnemonic(mnemonic);
  const bytes = new TextEncoder().encode(canonical);
  return sha256(bytes);
}

// --- helpers --------------------------------------------------------------

function bytesToHex(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i++) {
    out += (b[i]! >>> 4).toString(16) + (b[i]! & 0x0f).toString(16);
  }
  return out;
}
