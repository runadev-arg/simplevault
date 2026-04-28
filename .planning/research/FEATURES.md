# Password Manager + Secure Notes Feature Surface

Research catalog of feature surfaces across Bitwarden, 1Password, Proton Pass, Standard Notes, and KeePassXC. Each row is labelled **table-stake** (every serious vault ships it) or **differentiator** (only some ship it, or implementations vary widely). KeePassXC is included in the narrative where relevant; the comparison tables follow the requested four-column format.

> Note: WebFetch was denied during this research; the catalog below is compiled from prior knowledge of these products' publicly documented feature sets (vendor help centers, feature pages, and release notes through early 2026). Verify edge cases against the live docs before scoping decisions.

---

## 1. Credential Management

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| URL / username / password fields | Yes | Yes | Yes | No (notes app) | table-stake |
| TOTP / OTP storage + generation | Yes (paid) | Yes | Yes | No | table-stake |
| Notes field on credential | Yes | Yes | Yes | n/a | table-stake |
| Custom fields (text/hidden/boolean) | Yes | Yes | Yes | n/a | table-stake |
| File attachments on item | Yes (paid) | Yes | Yes | Yes | table-stake |
| Password generator — length & char classes | Yes | Yes | Yes | No | table-stake |
| Passphrase / diceware mode | Yes | Yes | Yes | No | table-stake |
| Pronounceable passwords | No | No | Yes (memorable) | No | differentiator |
| Strength meter (zxcvbn or similar) | Yes | Yes | Yes | No | table-stake |
| Password history per item | Yes | Yes | Yes | n/a | table-stake |
| Reuse detection across vault | Yes | Yes (Watchtower) | Yes (Pass Monitor) | n/a | table-stake |
| Breach detection (HIBP / proprietary) | Yes (HIBP) | Yes (Watchtower) | Yes (Pass Monitor + Sentinel) | No | table-stake |
| Password expiry / age warnings | Yes | Yes | Yes | n/a | differentiator |
| Email aliases / hide-my-email | No (Bitwarden Send is unrelated; integrates with SimpleLogin/Fastmail) | Yes (masked email via Fastmail) | Yes (SimpleLogin / hide-my-email) | No | differentiator |
| Passkey storage (FIDO2 credentials) | Yes | Yes | Yes | No | differentiator (now table-stake among password managers) |
| SSH key storage / agent | No | Yes | No | No | differentiator |
| Credit card / identity item types | Yes | Yes | Yes | No | table-stake (for password managers) |

KeePassXC: covers fields, attachments, generator (chars/passphrase), strength meter, TOTP, history, HIBP via offline file check, passkeys (recent).

---

## 2. Notes / Pages

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Plain secure notes | Yes | Yes | Yes | Yes | table-stake |
| Rich text (headings, bold, lists) | No | Limited | Limited | Yes | differentiator |
| Markdown editor | No | No | No | Yes | differentiator |
| Code blocks w/ syntax highlight | No | No | No | Yes | differentiator |
| Tables in notes | No | No | No | Yes (Plus editor) | differentiator |
| Inline images / embeds | No | Yes (documents) | No | Yes | differentiator |
| Note attachments | Yes | Yes | Yes | Yes | table-stake |
| Version history on notes | No | Yes (item history) | No | Yes (note history) | differentiator |
| Full-text search inside note body | Limited | Yes | Yes | Yes | differentiator |
| Tags / folders on notes | Folders | Tags + vaults | Vaults | Tags + nested | table-stake |
| Templates | No | Yes (item templates) | No | Limited | differentiator |
| Markdown import / export | No | No | No | Yes | differentiator |
| Block-based editor (Notion-like) | No | No | No | Partial | differentiator (rare) |
| Pinned / starred notes | Yes (favorite) | Yes | Yes | Yes | table-stake |

KeePassXC: plain notes only, no rich text; attachments yes; no version history beyond DB-level history.

---

## 3. Sharing Primitives

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Share entire vault / collection | Yes (Organizations) | Yes (Shared vaults) | Yes (Shared vaults) | No (single-user) | table-stake (for managers) |
| Share individual item to user | Yes | Yes (Item sharing) | Yes | No | table-stake |
| Share via one-time URL link | Yes (Send) | Yes (Psst! / Item share link) | Yes (Secure links) | No | differentiator |
| TTL / expiration on share | Yes | Yes | Yes | n/a | table-stake (for sharing) |
| View-only vs edit permissions | Yes | Yes | Yes | n/a | table-stake |
| Per-share password gate | Yes (Send) | Yes | Yes | n/a | differentiator |
| Recipient view counter / max views | Yes (Send) | Yes | Yes | n/a | differentiator |
| Share to non-account recipient (link) | Yes | Yes | Yes | No | differentiator |
| Encrypted file export to share offline | Yes | Yes (1PUX) | Yes | Yes | table-stake |
| Notification on receive / open | Yes (email) | Yes | Yes | n/a | differentiator |
| Per-user key wrapping for vault | Yes | Yes | Yes | n/a | table-stake (under hood) |
| Unanimous-vote deletion of shared item | No | No | No | No | unique |

KeePassXC: sharing is file-level only (KeeShare with shared groups via files on disk); no online sharing, no link sharing.

---

## 4. Auth & Account

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Email + master password signup | Yes | Yes (+ Secret Key) | Yes (Proton account) | Yes | table-stake |
| Login / logout | Yes | Yes | Yes | Yes | table-stake |
| Master password change w/ vault re-encrypt | Yes | Yes | Yes | Yes | table-stake |
| 2FA enrollment (TOTP) | Yes | Yes | Yes | Yes | table-stake |
| 2FA: WebAuthn / hardware key | Yes | Yes | Yes | Yes | table-stake |
| 2FA: Email / Duo / Yubico OTP | Yes | Limited | Limited | Limited | differentiator |
| Active sessions list | Yes | Yes | Yes | Yes | table-stake |
| Remote logout / revoke session | Yes | Yes | Yes | Yes | table-stake |
| Trusted device login (no master pw on trusted) | Yes (SSO trusted device) | Yes | No | No | differentiator |
| New-device login email alert | Yes | Yes | Yes | Yes | table-stake |
| SSO (SAML/OIDC) | Yes (paid) | Yes (paid) | Yes (paid) | No | differentiator |
| Biometric unlock (platform) | Yes | Yes | Yes | Yes | table-stake (clients) |
| Auto-lock timeout | Yes | Yes | Yes | Yes | table-stake |

---

## 5. Recovery & Emergency

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Recovery code at signup | No (master pw hint only) | Yes (Emergency Kit w/ Secret Key) | Yes (recovery phrase) | No | differentiator |
| Emergency contacts (delegated access) | Yes (paid) | No (deprecated) | No | No | differentiator |
| Account export (encrypted) | Yes | Yes (1PUX) | Yes | Yes | table-stake |
| Account export (plaintext JSON/CSV) | Yes | Yes | Yes | Yes | table-stake |
| Self-serve account deletion | Yes | Yes | Yes | Yes | table-stake |
| GDPR data export bundle | Yes | Yes | Yes | Yes | table-stake |
| Inheritance / legacy contact | No | No | No | No | differentiator (gap across all) |

KeePassXC: recovery is "keep your KDBX backed up"; no emergency contact concept.

---

## 6. Audit & Visibility

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Vault security score / health | Yes (Reports, paid) | Yes (Watchtower) | Yes (Pass Monitor) | No | table-stake (managers) |
| Weak password report | Yes | Yes | Yes | n/a | table-stake |
| Reused password report | Yes | Yes | Yes | n/a | table-stake |
| Old / unchanged password report | Yes | Yes | Yes | n/a | differentiator |
| Breach alert per item | Yes | Yes | Yes | No | table-stake |
| 2FA-eligible site report | Yes | Yes | Yes | n/a | differentiator |
| Personal audit log of own actions | Limited | Limited | Limited | Limited | differentiator (gap) |
| Org / shared-vault audit log | Yes (Event logs, paid) | Yes (Activity log, paid) | Limited | n/a | differentiator |
| Tamper-evident / hash-chained log | No | No | No | No | unique |
| Login history (timestamps + IP) | Yes | Yes | Yes | Yes | table-stake |

---

## 7. Admin / Operator (self-hosted relevance)

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Self-hosted server option | Yes (official + Vaultwarden) | No | No | Yes | differentiator |
| Invite-only registration | Yes (config flag) | n/a | n/a | Yes | table-stake (self-hosted) |
| User management (add/remove/disable) | Yes | Yes (cloud) | Yes (cloud) | Yes | table-stake |
| Organizational / team vaults | Yes | Yes | Yes | No | table-stake (managers) |
| Group-based access control | Yes | Yes | Yes | No | differentiator |
| Role-based admin (owner/admin/user) | Yes | Yes | Yes | Limited | table-stake |
| Backup / restore tooling | Yes (DB dump) | Cloud-managed | Cloud-managed | Yes (file) | table-stake (self-hosted) |
| Server health / status dashboard | Yes (admin panel) | n/a | n/a | Limited | differentiator |
| Directory sync (LDAP/SCIM) | Yes (paid) | Yes (paid) | Limited | No | differentiator |

---

## 8. UX Features

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Global search across items | Yes | Yes | Yes | Yes | table-stake |
| Favorites / pinned | Yes | Yes | Yes | Yes | table-stake |
| Recently accessed list | Yes | Yes | Yes | Yes | table-stake |
| Tags / labels | Limited | Yes | No | Yes (nested) | differentiator |
| Folders / nested folders | Yes | Yes (vaults) | Vaults | Yes | table-stake |
| Bulk actions (move/delete/share) | Yes | Yes | Yes | Yes | table-stake |
| Keyboard shortcuts | Yes | Yes | Yes | Yes | table-stake |
| Browser autofill extension | Yes | Yes | Yes | n/a | table-stake (managers, N/A v1 here) |
| Mobile apps (iOS/Android) | Yes | Yes | Yes | Yes | table-stake |
| Import: CSV | Yes | Yes | Yes | Yes | table-stake |
| Import: KeePass XML / KDBX | Yes | Yes | Yes | No | table-stake |
| Import: 1PUX / 1PIF | Yes | Yes (native) | Yes | No | differentiator |
| Import: LastPass / Dashlane / Chrome | Yes | Yes | Yes | No | table-stake |
| Dark mode | Yes | Yes | Yes | Yes | table-stake |
| Mobile-responsive web UI | Yes | Yes | Yes | Yes | table-stake |
| CLI client | Yes | Yes | No | No | differentiator |

---

## 9. Compliance / Privacy

| Feature | Bitwarden | 1Password | Proton Pass | Standard Notes | Stake |
|---|---|---|---|---|---|
| Public privacy policy | Yes | Yes | Yes | Yes | table-stake |
| Public ToS | Yes | Yes | Yes | Yes | table-stake |
| GDPR data deletion workflow | Yes | Yes | Yes | Yes | table-stake |
| Audit log retention policy stated | Yes | Yes | Yes | Limited | differentiator |
| Transparency report | Yes | Yes | Yes | No | differentiator |
| SOC 2 / ISO 27001 attestation | Yes | Yes | Yes | No | differentiator (N/A self-hosted) |
| Independent security audit (published) | Yes | Yes | Yes | Yes | table-stake |
| Open source codebase | Yes | No | Partial | Yes | differentiator |

---

## 10. Operational (self-hosted operator)

KeePassXC is a desktop app and skips most of these. Bitwarden (and the Vaultwarden community fork) and Standard Notes are the relevant comparators; 1Password and Proton Pass are SaaS-only.

| Feature | Bitwarden (self-host) | Vaultwarden | Standard Notes (self-host) | KeePassXC | Stake |
|---|---|---|---|---|---|
| Docker / docker-compose deployment | Yes | Yes | Yes | n/a | table-stake |
| Helm chart / k8s manifests | Yes | Community | Community | n/a | differentiator |
| Automatic backups (restic/borg/cron) | Manual | Manual | Manual | n/a | differentiator (often left to operator) |
| SSL via Let's Encrypt / ACME | Via reverse proxy | Via reverse proxy | Via reverse proxy | n/a | table-stake |
| Reverse proxy config docs (nginx/Caddy/Traefik) | Yes | Yes | Yes | n/a | table-stake |
| Secret rotation tooling (DB / JWT keys) | Manual | Manual | Manual | n/a | differentiator |
| Log rotation built-in | Limited | Limited | Limited | n/a | differentiator |
| Monitoring / metrics endpoint (Prometheus) | Limited | Limited | Limited | n/a | differentiator |
| Health check endpoint | Yes | Yes | Yes | n/a | table-stake |
| Migration scripts on version upgrade | Yes | Yes | Yes | n/a | table-stake |
| Admin web panel | Yes | Yes | Limited | n/a | differentiator |
| SMTP config for transactional email | Yes | Yes | Yes | n/a | table-stake |

---

## Features unique to SimpleVault's positioning

- **Unanimous-vote deletion of shared-vault items** with timeout-based override — no incumbent ships member-quorum gating on destructive actions.
- **Hash-chained / tamper-evident audit log** for shared-vault activity (append-only, cryptographically verifiable) — incumbents offer event logs but not chain integrity guarantees.
- **Per-user key wrapping with explicit re-wrap on membership change** surfaced as a first-class auditable event (not hidden infrastructure).
- **Notion-like rich-text pages stored under the same encryption envelope as credentials** — Standard Notes does rich text but no credentials; password managers do credentials but not block-style rich pages.
- **Self-hosted, family-scale (≤50 users) by design** — no billing surface, no org/team/enterprise tier separation, no SSO upsell; admin tooling tuned for a single operator running it for friends and family.
- **Deletion-with-timeout-override as a primitive** (vs. simple soft-delete + trash) — combining quorum and time-bound automatic resolution is novel.
