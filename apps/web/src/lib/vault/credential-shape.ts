import { z } from "zod";

/**
 * Phase 04 / Plan 04-10 — TypeScript + Zod for the in-blob plaintext shape
 * (DecryptedCredential).
 *
 * This is the JSON that lives INSIDE the per-credential XChaCha20-Poly1305
 * envelope (master_DEK as key, AAD bound to {label, sha256(email),
 * canonical-JSON({credentialId,vaultId,version})}). The server NEVER sees
 * any of these fields decrypted; only the client validates / normalises.
 *
 * `history[]` (REQ-VAULT-006 / INDEX truth 12): client-only password
 * rotation. Capped at 10. Old plaintext NEVER exits the encrypted blob —
 * see Plan 04-10 Task 3.
 */
export const HistoryEntrySchema = z.object({
  password: z.string(),
  changedAt: z.string(),
});

export const CustomFieldSchema = z.object({
  name: z.string().max(100),
  value: z.string().max(2000),
  hidden: z.boolean().default(false),
});

export const DecryptedCredentialSchema = z
  .object({
    name: z.string().min(1).max(200),
    urls: z.array(z.string().url()).max(10).default([]),
    username: z.string().max(200).default(""),
    password: z.string().max(1024).default(""),
    notes: z.string().max(10_000).default(""),
    custom_fields: z.array(CustomFieldSchema).max(20).default([]),
    is_favorite: z.boolean().default(false),
    history: z.array(HistoryEntrySchema).max(10).default([]),
  })
  .strict();

export type DecryptedCredential = z.infer<typeof DecryptedCredentialSchema>;
export type HistoryEntry = z.infer<typeof HistoryEntrySchema>;
export type CustomField = z.infer<typeof CustomFieldSchema>;

/** Empty-form initial value used by /credential/new. */
export function emptyCredential(): DecryptedCredential {
  return {
    name: "",
    urls: [],
    username: "",
    password: "",
    notes: "",
    custom_fields: [],
    is_favorite: false,
    history: [],
  };
}
