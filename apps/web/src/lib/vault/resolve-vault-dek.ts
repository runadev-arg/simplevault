import { keyStore } from "../auth/key-store";

/**
 * Phase 07 — resolve the encryption DEK for a vault.
 *
 * For the personal vault (no explicit vaultId or vaultId not in keyStore
 * under "vault_dek:${vaultId}"): falls back to "master_dek".
 * For shared vaults: returns the sealed-box-derived DEK stored at login /
 * invite-accept time.
 *
 * Returns undefined only if master_dek is also missing (vault locked).
 */
export function resolveVaultDek(vaultId?: string): Uint8Array | undefined {
  if (vaultId !== undefined) {
    const sharedDek = keyStore.getBytes(`vault_dek:${vaultId}`);
    if (sharedDek !== undefined) return sharedDek;
  }
  return keyStore.getBytes("master_dek");
}
