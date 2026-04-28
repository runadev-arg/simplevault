// Branded types so we don't pass a Ciphertext where a Plaintext is expected
export type Plaintext = Uint8Array & { readonly __brand: "Plaintext" };
export type Ciphertext = Uint8Array & { readonly __brand: "Ciphertext" };
export type Nonce = Uint8Array & { readonly __brand: "Nonce" };
export type Salt = Uint8Array & { readonly __brand: "Salt" };

export type SymmetricKey = Uint8Array & { readonly __brand: "SymmetricKey" };
export type WrappedKey = Uint8Array & { readonly __brand: "WrappedKey" };

export interface KdfParams {
  readonly memKiB: number;
  readonly iterations: number;
  readonly parallelism: number;
}

export interface EncryptedRecord {
  readonly ciphertext: Ciphertext;
  readonly nonce: Nonce;
  readonly aad: Uint8Array;
}

// BIP-39 24-word recovery phrase
export type RecoveryPhrase = string & { readonly __brand: "RecoveryPhrase" };
