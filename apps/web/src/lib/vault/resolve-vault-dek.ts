import { keyStore } from "../auth/key-store";

/**
 * Phase 07 — resolve the encryption DEK for a vault.
 *
 * When `vaultId` is provided (shared vault context), returns
 * `vault_dek:${vaultId}` from keyStore, or `undefined` if the DEK is not
 * loaded (vault locked / invite not yet accepted). Does NOT fall back to
 * `master_dek` — falling back would silently encrypt shared-vault content
 * under the personal vault key (FINDING-0079).
 *
 * When `vaultId` is absent (personal vault context), returns `master_dek`.
 */
export function resolveVaultDek(vaultId?: string): Uint8Array | undefined {
  if (vaultId !== undefined) {
    return keyStore.getBytes(`vault_dek:${vaultId}`);
  }
  return keyStore.getBytes("master_dek");
}
