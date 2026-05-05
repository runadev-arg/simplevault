import {
  buildVaultPageAad as buildVaultPageAadImpl,
  decrypt as aeadDecrypt,
  encrypt as aeadEncrypt,
  ready,
  type VaultPageAadInput,
} from "@simplevault/crypto/browser";
import sodium from "libsodium-wrappers-sumo";

import { AAD_LABEL_VAULT_PAGE } from "./aad-labels";

/**
 * Phase 05 Plan 03 — browser-only encrypt/decrypt wrappers around
 * `aead.encrypt` / `aead.decrypt` for vault page blobs (TipTap JSON).
 *
 * Sibling parity with `credential-cipher.ts`. The AAD is built by
 * `buildVaultPageAad` from `@simplevault/crypto` with the label INJECTED
 * from `aad-labels.ts` (single source of truth; FINDING-0026 closure
 * relies on this — never duplicate the literal here). The nonce is 24
 * random bytes per encrypt (XChaCha20-Poly1305 IETF, generated inside
 * `aead.encrypt`).
 */

export interface PageBlob {
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

/**
 * Convenience: build the per-page AAD using the FROZEN label imported
 * from `aad-labels.ts`.
 */
export function buildVaultPageAad(input: VaultPageAadInput): Uint8Array {
  return buildVaultPageAadImpl(input, AAD_LABEL_VAULT_PAGE);
}

/**
 * Encrypt a TipTap JSON plaintext under master_DEK with the supplied AAD.
 * The 24-byte nonce is generated inside `aead.encrypt` (libsodium
 * randombytes_buf), guaranteeing no reuse.
 */
export async function encryptPage(
  tiptapJsonString: string,
  masterDek: Uint8Array,
  aad: Uint8Array,
): Promise<PageBlob> {
  await ready();
  const pt = sodium.from_string(tiptapJsonString);
  const blob = await aeadEncrypt(pt, masterDek, aad);
  return { ciphertext: blob.ciphertext, nonce: blob.nonce };
}

/**
 * Decrypt a page blob. Throws on tag mismatch (mutated ciphertext, wrong
 * AAD, wrong key, mutated nonce). Returns the original UTF-8 JSON string.
 */
export async function decryptPage(
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  masterDek: Uint8Array,
  aad: Uint8Array,
): Promise<string> {
  await ready();
  const pt = await aeadDecrypt({ ciphertext, nonce }, masterDek, aad);
  return sodium.to_string(pt);
}

interface TipTapTextNode {
  type: "text";
  text?: string;
}

interface TipTapHeadingNode {
  type: "heading";
  attrs?: { level?: number };
  content?: ReadonlyArray<TipTapTextNode | { type: string }>;
}

interface TipTapDoc {
  type?: string;
  content?: ReadonlyArray<unknown>;
}

function isTextNode(n: unknown): n is TipTapTextNode {
  return (
    typeof n === "object" &&
    n !== null &&
    (n as { type?: unknown }).type === "text"
  );
}

function isHeadingNode(n: unknown): n is TipTapHeadingNode {
  return (
    typeof n === "object" &&
    n !== null &&
    (n as { type?: unknown }).type === "heading"
  );
}

/**
 * Extracts the title from a TipTap doc: the concatenated `text` content
 * of the FIRST `heading` node with `attrs.level === 1`. Returns `""`
 * when no such heading exists, the heading has no text children, or the
 * input is malformed.
 *
 * Accepts either a parsed object or the JSON-string form (callers vary —
 * the editor hands us an object, the persisted blob round-trips through
 * a string).
 */
export function extractTitle(tiptapJson: string | object): string {
  let doc: TipTapDoc;
  if (typeof tiptapJson === "string") {
    try {
      doc = JSON.parse(tiptapJson) as TipTapDoc;
    } catch {
      return "";
    }
  } else {
    doc = tiptapJson as TipTapDoc;
  }
  const content = doc?.content;
  if (!Array.isArray(content)) return "";
  for (const node of content) {
    if (!isHeadingNode(node)) continue;
    if (node.attrs?.level !== 1) continue;
    const children = node.content;
    if (!Array.isArray(children)) return "";
    let buf = "";
    for (const c of children) {
      if (isTextNode(c) && typeof c.text === "string") {
        buf += c.text;
      }
    }
    return buf;
  }
  return "";
}
