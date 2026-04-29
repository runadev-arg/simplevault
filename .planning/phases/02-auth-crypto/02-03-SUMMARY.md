# Plan 02-03 Summary — BIP-39 + Key Hierarchy + Recovery Wrap

**Status:** DONE 2026-04-28
**Mode:** TDD (RED → GREEN per task; refactor folded into GREEN)
**Tests:** 53/53 green across 5 suites (`bip39.test.ts` 13, `key-hierarchy.test.ts` 17, plus prior 23)
**Browser parity:** ZERO `node:*` / `crypto` / `buffer` imports in `dist/*.js`
**Commits:** 4 atomic — `7c7d675` RED bip39 / `2bb7d11` GREEN bip39 / `aebe4f4` RED key-hierarchy / `61c6c6a` GREEN key-hierarchy

---

## Public API exposed (consumers: 02-04 sealed-box, 02-07 signup, 02-08 login, 02-10 web)

```ts
// bip39.ts
generateMnemonic(): string                                  // sync; uses libsodium randombytes_buf entropy
generateMnemonicAsync(): Promise<string>                    // boot-safe variant that awaits ready()
validateMnemonic(m: string): boolean
mnemonicToSeed(m: string, passphrase = ""): Promise<Uint8Array>   // 64-byte BIP-39 seed
computeRecoveryLookupHash(m: string): Uint8Array            // 32-byte sha256 of canonical(m); CLIENT-ONLY inner half

// key-hierarchy.ts
AAD_VERSION = 0x01
encodeAad(params: Argon2Params, contextId: Uint8Array): Uint8Array

deriveMasterKek({ password, secretKey, email, userArgonSalt, argon2Params? }): Promise<Uint8Array>  // 32 B
deriveRecoveryKek({ mnemonic, userId }): Promise<Uint8Array>                                        // 32 B

wrapKey(plaintextKey, wrappingKey, aad): Promise<{ ciphertext, nonce }>
unwrapKey(wrapped, wrappingKey, aad): Promise<Uint8Array>
```

Both surfaces re-exported through `src/browser.ts` and `src/node.ts` (parity verified by per-suite barrel-parity tests).

---

## AAD wire format (LOAD-BEARING — Plan 07 server signup MUST replicate byte-for-byte)

```
aad = version_byte                  (1 B, currently 0x01)
   || memoryKiB_be32                (4 B, big-endian uint32)
   || iterations_be32               (4 B, big-endian uint32)
   || parallelism_be32              (4 B, big-endian uint32)
   || context_id_bytes              (variable, e.g. user_id UUID as UTF-8 text)
```

Total fixed prefix = 13 bytes. For `users.wrapped_master_dek` and `users.wrapped_master_dek_recovery`, `contextId = enc.encode(user_id_uuid_string)`. Argon2 params are baked in so a DB-side downgrade of `users.argon_memory_kib` breaks the AEAD tag on every unwrap attempt — this is the load-bearing AAD-downgrade defence verified by `key-hierarchy.test.ts`.

For item-level encryption (Phase 04+), use `contextId = enc.encode(`${vault_id}|${item_id}|${item_version}`)` — the same `encodeAad` function applies, just with a different context id.

---

## HKDF info-strings (frozen for v1)

| Purpose         | info string                          |
|-----------------|--------------------------------------|
| master_seed     | `"simplevault.v1.master_seed"`       |
| recovery_KEK    | `"simplevault.v1.recovery_kek"`      |

Bumping these is a hard wire-format break. Use a new info-string + bump `AAD_VERSION` and migrate at next major.

---

## Key hierarchy summary

```
master_seed     = HKDF-SHA256(ikm = secret_key,
                              salt = lower(email),
                              info = "simplevault.v1.master_seed",  L=32)

argon_salt[16]  = master_seed[0..16] XOR user_argon_salt[16]   // user_argon_salt is 16 B in users table

master_KEK      = Argon2id(password_utf8, argon_salt, params, 32)

wrapped_master_DEK
                = XChaCha20-Poly1305(key=master_KEK,
                                     msg=master_DEK,
                                     aad=encodeAad(params, user_id_bytes))

recovery_KEK    = HKDF-SHA256(ikm=mnemonicToSeed(mnemonic),
                              salt=user_id,
                              info="simplevault.v1.recovery_kek", L=32)

wrapped_master_DEK_recovery
                = XChaCha20-Poly1305(key=recovery_KEK,
                                     msg=master_DEK,    // SAME master_DEK
                                     aad=encodeAad(params, user_id_bytes))
```

The XOR-salt construction (master_seed XOR user_argon_salt) ties the Argon2 salt to **both** the secret_key (via master_seed via HKDF) and the server-stored salt — neither alone derives the right Argon2 salt, defending against half-stolen secrets.

The recovery path skips Argon2 because the BIP-39 seed already has 256 bits of entropy; HKDF is sufficient and lets recovery succeed in <100 ms vs the ~750 ms Argon2 path.

---

## Plan 07 (signup API) consumption checklist

The browser at signup will produce these client-side and POST them to the server:

| Field                              | Client computes                                                                                          | Sent to server? |
|------------------------------------|----------------------------------------------------------------------------------------------------------|------------------|
| `users.argon2_secret_key_hash`     | `Argon2id(secret_key, SERVER_ARGON_SALT, params, 32)` — server salt fetched at signup-init               | YES |
| `users.user_argon_salt` (16 B)     | `randombytes_buf(16)`                                                                                    | YES |
| `users.wrapped_master_dek`         | `wrapKey(master_DEK, master_KEK, encodeAad(params, user_id_bytes))` packed as `{nonce, ciphertext}`      | YES |
| `users.wrapped_master_dek_recovery`| `wrapKey(master_DEK, recovery_KEK, encodeAad(params, user_id_bytes))`                                    | YES |
| `users.recovery_hmac` (inner half) | `computeRecoveryLookupHash(mnemonic)` — server then applies `HMAC-SHA256(SERVER_RECOVERY_HMAC_SECRET, .)` | INNER ONLY |
| `users.argon_memory_kib`/`_t`/`_p` | the calibrated `params` tuple                                                                            | YES (record AAD)|
| `users.user_pub_key` + wrapped sks | **deferred to Plan 02-04** (X25519 sealed-box)                                                            | — |

**Server-side invariant preserved:** server never sees `master_password`, `secret_key`, `recovery_phrase`, `master_KEK`, `master_DEK`, or `recovery_KEK`. The crypto package's `node.ts` barrel exports the same surface, but the SECRETS-AT-REST consumers (signup endpoint) only call `encodeAad` to verify AAD shape and `computeRecoveryLookupHash` is browser-only by convention (no enforcement at type level — Plan 07 must keep its server route from invoking it).

---

## Versions

| Dep                       | Version |
|---------------------------|---------|
| `bip39`                   | 3.1.0   |
| `@noble/hashes`           | 1.8.0   |
| `libsodium-wrappers-sumo` | 0.7.16  |

---

## Truths (all 7 TRUE)

1. ✅ BIP-39 generate produces 24-word mnemonic; validate accepts it; non-wordlist word + checksum-broken last word fail validation.
2. ✅ `mnemonicToSeed` returns 64 bytes per BIP-39 spec (deterministic in passphrase).
3. ✅ `deriveMasterKek({password, secretKey, email, userArgonSalt, argon2Params})` returns 32-byte key per CRYPTO-STACK §3 (HKDF → XOR-salt → Argon2id). Email is case-insensitive.
4. ✅ `deriveRecoveryKek({mnemonic, userId})` returns 32-byte key independent of password (HKDF-SHA256 over mnemonicToSeed).
5. ✅ Master-path round-trip: derive master_KEK → wrap master_DEK → unwrap → identical bytes.
6. ✅ Recovery-path round-trip: wrap master_DEK with recovery_KEK → unwrap with re-derived recovery_KEK → identical bytes. Dual-path test asserts SAME master_DEK reachable via either path.
7. ✅ AAD downgrade defence: mutating params bytes, contextId, OR version byte in AAD all cause `unwrapKey` to throw (tag mismatch).

---

## Deviations

- **Test mutation strategy:** initial RED bip39 test mutated word[0] to a different valid wordlist word, which can occasionally still validate against a different entropy. Replaced with two stronger mutation tests: (a) non-wordlist-word typo, (b) loop-up-to-16 last-word swap (last-word swap may rarely land on a checksum-valid alt; 16 attempts make false-pass probability negligible). Caught by GREEN run, not by RED. Auto-applied (rule 1).
- **Refactor commits:** folded into GREEN — barrel re-exports + parity tests are the only refactor candidates and they ship in the same commits as the impl. Same pattern as 02-02. Auto-applied (rule 2).
- No rule-4 deviations. No checkpoints.
