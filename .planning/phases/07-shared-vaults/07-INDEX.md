# Phase 07 — Shared Vaults (MVP Track)

**Goal (must be TRUE):** A user can create a named shared vault, invite another
registered user by email, and the invitee can accept and immediately read/write
credentials inside that vault — with each member holding their own sealed-box
copy of the vault DEK, and server never seeing plaintext.

**Key decisions:**
- Vault DEK = 32 random bytes generated client-side by the vault owner at
  creation time. Per-member copy stored server-side as `sealed_box(vault_dek,
  member.kx_pk)` — server only ever sees the ciphertext.
- `users.user_pub_key` (already stored since Phase 02) is the X25519 kx_pk
  used for sealing. No new key material needed.
- Personal vault credential routes (`/credential/new?vaultId=...`) accept
  an optional `vaultId` query param; when present, the DEK is loaded from
  `keyStore.getBytes("vault_dek:${vaultId}")` instead of `master_dek`.
- Shared vault pages (Phase 05 `/pages`) use the same DEK override — no
  route duplication needed.
- Revoke = delete membership row. Vault DEK rotation on revoke is
  **DEFERRED** to post-MVP (complex n-party re-wrap; noted in FINDINGS).

**Wave map:**

| Wave | Plans | Can run in parallel |
|------|-------|---------------------|
| 1 | 07-01 (DB), 07-03 (crypto helpers) | yes |
| 2 | 07-02 (API module) | after 07-01 |
| 3 | 07-04 (web vaults list+create), 07-05 (web invite+members), 07-06 (web DEK plumbing) | after 07-02, 07-03 |

**Plans:**
- [07-01-PLAN.md](07-01-PLAN.md) — DB: `vaults.name` + `vault_memberships` + migration 0005
- [07-02-PLAN.md](07-02-PLAN.md) — API: VaultSharingModule (create, list, invite, accept, revoke)
- [07-03-PLAN.md](07-03-PLAN.md) — Crypto: `vault-key.ts` (wrap/unwrap/generate helpers)
- [07-04-PLAN.md](07-04-PLAN.md) — Web: `/vaults` list + `/vaults/new` create form + `/vaults/:id` shared credential list
- [07-05-PLAN.md](07-05-PLAN.md) — Web: `/invites` + `/vaults/:id/invite` + `/vaults/:id/members`
- [07-06-PLAN.md](07-06-PLAN.md) — Web: DEK plumbing — credential + page routes use vault_dek when vaultId query param present
