/**
 * In-memory ONLY key/secret store for the signup + login flows.
 *
 * INVARIANTS (LOAD-BEARING):
 *   - NEVER write any of these values to localStorage / sessionStorage /
 *     IndexedDB / cookies / any persistent surface. They live in JS heap
 *     for the lifetime of the SPA tab and are wiped at flow end.
 *   - `wipe()` overwrites every Uint8Array with zeros (best-effort
 *     defence; the JS engine may have already copied values into other
 *     buffers, but we minimise the window).
 *   - Strings (master_password, mnemonic) cannot be reliably zeroed in
 *     JavaScript — the engine interns/copies them. Best we can do is
 *     `delete` the property and hope GC reclaims them quickly.
 *
 * Scope: a single Map per tab. Holds:
 *   - master_password : string
 *   - secret_key      : Uint8Array(16)
 *   - mnemonic        : string (BIP-39 24 words, NFKD-normalised)
 *   - master_kek      : Uint8Array(32)  (post-derive)
 *   - master_dek      : Uint8Array(32)  (post-derive)
 *   - recovery_kek    : Uint8Array(32)  (post-derive)
 *   - signing_sk      : Uint8Array(64)  (Ed25519)
 *   - kx_sk           : Uint8Array(32)  (X25519)
 */

type StoredValue = string | Uint8Array;

const _store = new Map<string, StoredValue>();

export function set(key: string, value: StoredValue): void {
  _store.set(key, value);
}

export function get(key: string): StoredValue | undefined {
  return _store.get(key);
}

export function getBytes(key: string): Uint8Array | undefined {
  const v = _store.get(key);
  return v instanceof Uint8Array ? v : undefined;
}

export function getString(key: string): string | undefined {
  const v = _store.get(key);
  return typeof v === "string" ? v : undefined;
}

export function has(key: string): boolean {
  return _store.has(key);
}

export function entries(): IterableIterator<[string, StoredValue]> {
  return _store.entries();
}

/**
 * Zero-overwrite all Uint8Array values, then drop everything from the Map.
 * Strings cannot be zeroed in JS — drop them and rely on GC.
 */
export function wipe(): void {
  for (const [, value] of _store) {
    if (value instanceof Uint8Array) {
      value.fill(0);
    }
  }
  _store.clear();
}

export const keyStore = { set, get, getBytes, getString, has, entries, wipe };
