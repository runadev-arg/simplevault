# SimpleVault — Security Pitfalls & Lessons Learned

> Adversary model: targeted, web-skilled, motivated attacker. NOT nation-state.
> Scope: self-hosted password manager + Notion-like notes, E2E encrypted, NestJS + Next.js, Docker on VPS.
> Note: WebFetch was unavailable in this research session; citations below reference well-known public disclosures, CVE IDs, and OWASP cheatsheet titles. URLs should be verified by the auditor before publication.

---

## 1. LastPass 2022–2023 breaches

**Incident.** Two-stage breach. **August 2022:** attacker stole source code and internal docs from LastPass dev environment. **November–December 2022:** attacker pivoted using stolen dev credentials and a vulnerable third-party media software package (Plex, CVE-2020-5741 era RCE) installed on a **Senior DevOps engineer's home computer** to keylog the engineer's LastPass corporate vault master password. Attacker exfiltrated a backup of the customer vault database from AWS S3.

**What was leaked.**
- Encrypted vault blobs (passwords, notes — encrypted with user-derived key).
- **Unencrypted** URL fields, email, billing address, IP history, vault metadata.
- Customer KDF iteration counts.

**Root causes.**
1. **URLs stored in plaintext** in the vault schema "for performance" (autofill matching server-side, deduping). This leaked browsing/identity profiles per user.
2. **KDF iteration count was per-user and inconsistent** — legacy users had as low as 1 or 500 PBKDF2 iterations while OWASP recommended 100k+ at the time. LastPass never force-migrated.
3. **Single trusted operator endpoint** (the engineer's home machine) had unrestricted production access. No bastion, no per-action MFA on prod.
4. **Backup egress** was not gated by additional out-of-band approval.

**Refs.** LastPass blog "Notice of Recent Security Incident" (Aug 25, 2022); "Security Incident Update and Recommended Actions" (Mar 1, 2023); CISA alert; Krebs on Security write-up.

**SimpleVault mitigations.**
- **Encrypt every field that touches the vault**, including URL/title/icon/tags. Server only sees opaque ciphertext + an HMAC-derived bucket id for search.
- **One global KDF policy** (Argon2id, m=64MiB, t=3, p=4 minimum) enforced server-side; if params change, force re-derivation on next login.
- Operator (you) must use a **separate, hardened admin laptop** for any prod SSH session — not the daily-driver dev machine. Disable Plex/streaming/random Electron apps on that machine. Full-disk encryption + auto-lock.
- Backups encrypted with a key **the running app does not have** (restic + offline password). See §15.
- Document an **operator break-glass** with cooldown: any DB dump or volume export requires re-authenticating with a hardware key.

---

## 2. Bitwarden iframe / autofill (2023)

**Incident.** Flashpoint disclosure (Mar 2023). Bitwarden browser extension's auto-fill-on-page-load feature would fill credentials into iframes embedded on the saved-domain page even when the iframe pointed to an attacker-controlled origin (e.g. a compromised ad network iframe on `legit.com`). Reported as known-but-unfixed for years; Bitwarden later disabled cross-origin iframe autofill by default.

**Root cause.** Trust decision was made on **top frame origin** rather than the **iframe URL**. SOP allows the iframe to receive the typed value via JS in its own document.

**Applicability.** SimpleVault v1 has **no browser extension**, so direct exposure is zero. Document for v2.

**v2 rules (when extension lands).**
- Autofill defaults **off**, requires explicit user action (keyboard shortcut + visible UI).
- Match credentials against **iframe origin**, not top frame; refuse cross-origin frames.
- Refuse autofill on `http:` (non-TLS), `data:`, `blob:`, sandboxed iframes.
- No "auto-submit" ever.

---

## 3. 1Password Cloudflare incident & "Secret Key"

**Incident.** Cloudbleed (Feb 2017, Tavis Ormandy / Project Zero) leaked random Cloudflare-proxied response memory across the internet, including 1Password traffic. 1Password publicly stated **no customer vault data was at risk** because of their two-secret model.

**Two-secret model.** Vault key = `KDF(master_password) XOR Secret_Key`. The **Secret Key** is a 128-bit value generated on the device at signup, never sent to 1Password servers, stored locally + printed on the Emergency Kit. Even a full server breach + leaked TLS does not yield a guessable key, because the attacker would need the Secret Key (high entropy) in addition to the master password.

**Should SimpleVault adopt?** **Yes, recommended.** Cross-reference `CRYPTO.md`. Concretely:
- At account creation, generate a 256-bit `account_secret` client-side.
- `vault_key = Argon2id(password, salt=server_salt) XOR HKDF(account_secret, "vault")`.
- Never transmit `account_secret`. Force user to download an "Emergency Kit" PDF/printable.
- Logging in on a new device requires entering both password and account_secret (paste once, then stored in OS keychain via WebAuthn-PRF or device-bound key).

Trade-off: worse UX (recovery requires the Kit). For a self-hosted product targeting motivated users, this is an acceptable price.

---

## 4. Standard Notes / Joplin sync conflict pitfalls

**Pattern.** End-to-end encrypted notes app cannot diff/merge ciphertext server-side. Standard Notes resolves conflicts by **storing both versions as separate items** ("Conflicted copy of …"). Joplin uses a similar duplicate-on-conflict scheme. Pitfalls observed:
- Silent overwrite if `updated_at` precision is too coarse (seconds, multi-device same-second saves).
- Lost edits when a stale client replays a write because the server has no version check.
- Client-side merge logic that decrypts both versions on the client is correct; server-side last-write-wins is dangerous.

**SimpleVault recommendation.**
- Use **optimistic locking with a monotonic `version` int per item** + `If-Match: <version>` on `PUT`.
- On version mismatch return `409 Conflict` with both ciphertexts; client decrypts both and shows a merge UI (for notes) or "keep both" (for credentials).
- For collaborative real-time editing of notes (later phase), use **CRDT (Yjs) over encrypted document with shared Yjs-room key** — server stores opaque updates; do not attempt server-side merging.
- Never trust client-supplied `updated_at`; server stamps it.

---

## 5. JWT pitfalls

**Hall of shame.**
- **`alg: none`** acceptance — auth0/jsonwebtoken pre-4.0 (CVE-2015-9235), many libs.
- **HS/RS confusion** — server using public RSA key as HMAC secret (CVE-2016-10555 and friends).
- **`kid` header path traversal / SQLi** — pulling key by attacker-controlled id.
- **Long-lived tokens** with no revocation, e.g. 30-day access tokens stored in `localStorage`, stolen via any XSS.
- **Refresh token without rotation** — stolen refresh = permanent account takeover.
- **JWT in `localStorage`** — readable by any XSS payload.

**SimpleVault checklist.**
- [ ] Use `jose` library, **explicitly pin `alg`** on verify: `jwtVerify(token, key, { algorithms: ['EdDSA'] })`. Never accept `alg` from header at face value.
- [ ] Prefer **EdDSA (Ed25519)** signing keys; rotate quarterly; embed `kid` and validate against an allowlist map.
- [ ] **Access token TTL ≤ 15 min**; **refresh token TTL ≤ 14 days**, **rotated on every use**, family-tracked. If a previously-used refresh token is presented again → revoke entire family + alert user (replay detection).
- [ ] Tokens in **HttpOnly, Secure, SameSite=Strict cookies**. No `localStorage`, no `sessionStorage`.
- [ ] Include `aud`, `iss`, `iat`, `exp`, `jti`. Validate all on every request.
- [ ] Server-side `jti` denylist for `logout-all` (only needed if access TTL > a few minutes — keep it short to avoid the list).
- [ ] No PII in payload; vault data never in JWT.

---

## 6. CSRF in cookie-auth APIs

**Misconception.** "SameSite=Lax is enough." It is **not**: top-level navigations with `POST` are blocked by Lax, but a `<form action="https://vault/api/items" method="POST">` submitted by user click on attacker site… actually Lax DOES block this. However:
- Lax allows **GET** with side effects (don't use GET for mutation, but reality: many do).
- Subdomain takeover or any same-site XSS bypasses SameSite entirely.
- Some browsers / older clients honor Lax inconsistently.

**SimpleVault rule.** **SameSite=Strict** + **double-submit CSRF token** for every state-changing endpoint.

**NestJS guard sketch.**

```ts
// csrf.guard.ts
@Injectable()
export class CsrfGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;
    const cookieToken = req.cookies['csrf'];
    const headerToken = req.header('x-csrf-token');
    if (!cookieToken || !headerToken) throw new ForbiddenException('csrf');
    const a = Buffer.from(cookieToken);
    const b = Buffer.from(headerToken);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      throw new ForbiddenException('csrf');
    }
    return true;
  }
}
```

CSRF cookie issued at login: `Set-Cookie: csrf=<32B random>; Secure; SameSite=Strict; Path=/` (NOT HttpOnly so JS can read+echo into header). Auth cookie remains HttpOnly. Apply guard globally; allow opt-out only for explicit public endpoints.

Additionally: validate `Origin`/`Referer` against the configured app origin as a belt-and-suspenders check.

---

## 7. CSP for Next.js App Router

**Common mistakes.**
- `style-src 'unsafe-inline'` because TailwindJIT injects `<style>`. Fix with **per-request nonce**.
- `script-src 'unsafe-eval'` to support `lodash.template`, old `vue`, some Markdown libs.
- Allowing `cdn.jsdelivr.net` or Google Fonts — any compromise of those CDNs = code exec in your origin.
- Forgetting `frame-ancestors 'none'` (clickjacking).
- Forgetting `base-uri 'none'` (DOM-clobbering of `<base>`).

**Recommended headers (Next.js App Router via middleware):**

```http
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'nonce-{NONCE}' 'strict-dynamic';
  style-src 'self' 'nonce-{NONCE}';
  img-src 'self' data: blob:;
  font-src 'self';
  connect-src 'self';
  frame-ancestors 'none';
  base-uri 'none';
  form-action 'self';
  object-src 'none';
  upgrade-insecure-requests;
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=(), clipboard-read=(self), clipboard-write=(self)
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

Generate nonce in `middleware.ts`, pass via header to RSC, render with `<Script nonce={nonce}>`. Self-host all fonts. No third-party script sources, period.

---

## 8. Account enumeration

**Pitfalls.**
- Login: "User not found" vs "Wrong password" → enumeration.
- Signup: "Email already taken" → enumeration.
- Password reset: "No such email" vs "Email sent" → enumeration.
- Timing: 200ms when user exists (Argon2 ran), 5ms when not (early return) → **timing enumeration**.
- 2FA: showing "Enter your TOTP" only for accounts that have 2FA → enumeration of high-value targets.

**SimpleVault rules.**
- Login error: **always** "Invalid email or password" (single 401, identical body, identical headers).
- Signup: send a confirmation email regardless; if the address is already registered, send a "someone tried to sign up with your email" email instead. UI shows the same "check your inbox" screen.
- Reset: "If an account exists for that email, we've sent reset instructions."
- 2FA: after first-factor success, ALWAYS proceed to a second-factor screen (display TOTP prompt even if user has none — accept any 6-digit, then redirect to "no 2FA configured, you're in"). Or simpler: enforce 2FA enrollment for all users after first login; then 2FA prompt is universal.
- Timing floor: see §9.

---

## 9. Timing attacks on login

**Argon2** with fixed parameters has roughly constant timing — good. The leak is the **lookup branch**: if the user does not exist, you skip Argon2 and respond fast.

**Pattern.**

```ts
const user = await users.findByEmail(email);
const hash = user?.passwordHash ?? DUMMY_ARGON2_HASH; // pre-computed at boot
const ok = await argon2.verify(hash, password); // always runs
const valid = !!user && ok;

// Floor the response time
const elapsed = Date.now() - start;
const floor = 350; // ms, > p99 of argon2 verify
if (elapsed < floor) await sleep(floor - elapsed);

if (!valid) throw new UnauthorizedException('Invalid email or password');
```

`DUMMY_ARGON2_HASH` is a hash of a random string generated at server boot, with the same params. Use `crypto.timingSafeEqual` for any token comparison.

---

## 10. Rich-text editor XSS

**Historical.** Quill `<= 1.3.7` mXSS via clipboard (CVE-2021-3163), Draft.js had several `convertFromHTML` issues, TipTap link extension `href` not sanitized in older versions (pre-2.x), CKEditor mXSS several.

**Rules for SimpleVault note editor.**
- Storage format = **TipTap JSON** (ProseMirror doc), never HTML.
- Render via React reconciliation from JSON; never `dangerouslySetInnerHTML`.
- **Schema allowlist:** explicit list of nodes (paragraph, heading, list, code, blockquote, link, image, hr) and marks (bold, italic, code, strike, underline). Reject unknown.
- Sanitize `link.href`: allow only `https://`, `http://`, `mailto:`. Block `javascript:`, `data:`, `vbscript:`, `file:`. Apply at **schema parse time AND render time**.
- Image `src`: allow only `https://` and `data:image/(png|jpeg|gif|webp);base64,...`; size cap.
- Defensive: pass any rendered HTML chunk through `sanitize-html` with the same allowlist.
- Block `<script>`, `<iframe>`, `<object>`, `<embed>`, `<form>`, `on*` attributes at the schema level.
- Pin TipTap and ProseMirror exact versions; subscribe to GHSA notifications.

---

## 11. postMessage, DOM clobbering, clipboard

**Pitfalls.** `window.addEventListener('message', ...)` without origin check → cross-origin code injection. DOM clobbering: `<form id="config"><input name="apiBase" value="https://evil/">` → `window.config.apiBase` overrides JS variables. Modern React mostly insulates, but third-party widgets may not.

**SimpleVault.** No `postMessage` listeners in v1. If added (OAuth popup), strict origin check + structured clone validation.

**Clipboard auto-clear** (passwords copied to clipboard linger and are stolen by any clipboard-reading app):

```ts
async function copyPasswordTemporarily(pw: string, ttlMs = 30_000) {
  await navigator.clipboard.writeText(pw);
  setTimeout(async () => {
    try {
      const current = await navigator.clipboard.readText();
      if (current === pw) await navigator.clipboard.writeText('');
    } catch { /* permission lost; user has navigated away */ }
  }, ttlMs);
}
```

Show a visible countdown UI. On tab `visibilitychange` to hidden, clear immediately.

---

## 12. Supply-chain attacks

**Roll call.**
- `event-stream` (2018) — `flatmap-stream` payload targeted Copay BTC wallet.
- `ua-parser-js` (Oct 2021, CVE-2021-23337-adjacent) — npm account hijack, cryptominer + credential stealer.
- `node-ipc` (Mar 2022, CVE-2022-23812) — maintainer protestware, wiped files on RU/BY IPs.
- `ctx` (May 2022) — typosquat-like hijack stealing env vars.
- `colors`/`faker` (Jan 2022) — maintainer self-sabotage.
- `xz-utils` (Mar 2024, CVE-2024-3094) — multi-year social engineering supply chain compromise.

**Mitigations.**
- `pnpm install --frozen-lockfile` in CI; commit `pnpm-lock.yaml`.
- Pin **exact versions** in `package.json` (no `^`, no `~`) for security-critical deps (`argon2`, `jose`, `tiptap`, `sanitize-html`, `nestjs/*`).
- `pnpm audit --audit-level=moderate` and `npm audit signatures` in CI; fail build on findings.
- Use `socket.dev` PR bot or `Snyk` for typosquat / postinstall detection.
- `pnpm.overrides` to force-patch transitive deps with known CVEs.
- `--ignore-scripts` for any non-trusted dep; review every `postinstall`.
- Prefer deps with: >1M downloads/week, multiple maintainers, recent commits, OSSF Scorecard ≥ 7.
- CI gate: `dependency-supply-chain-auditor` agent reviews every dep bump PR.
- Generate SBOM (`cyclonedx-npm`) on each release, store with artifact.

---

## 13. Docker hardening common misses

**Common misses.** Container runs as root; Postgres `5432` published to `0.0.0.0`; no `mem_limit`/`pids_limit`; `.env` baked into image layer; writable root FS; full Linux capabilities; `/var/run/docker.sock` mounted into a container; everything on default bridge network.

**docker-compose.yml hardening checklist.**

```yaml
services:
  api:
    image: simplevault/api:1.2.3@sha256:...   # pin digest
    user: "10001:10001"                        # non-root
    read_only: true
    tmpfs:
      - /tmp:size=64m
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
      - seccomp=./seccomp-default.json
    mem_limit: 512m
    pids_limit: 200
    restart: unless-stopped
    networks: [internal]
    environment:
      - NODE_ENV=production
    secrets:
      - db_password
      - jwt_signing_key
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:3000/healthz"]

  db:
    image: postgres:16.4-alpine@sha256:...
    user: "70:70"
    read_only: true
    tmpfs: [/tmp, /var/run/postgresql]
    cap_drop: [ALL]
    cap_add: [CHOWN, SETUID, SETGID, DAC_OVERRIDE, FOWNER]
    networks: [internal]                       # NO ports: section
    volumes:
      - pgdata:/var/lib/postgresql/data
    secrets: [db_password]
    environment:
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password

  caddy:
    image: caddy:2-alpine@sha256:...
    networks: [internal, edge]
    ports: ["443:443", "80:80"]
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    read_only: true

networks:
  internal: { internal: true }
  edge: {}

secrets:
  db_password:    { file: ./secrets/db_password }
  jwt_signing_key:{ file: ./secrets/jwt_signing_key }
```

Rules: **never** mount `docker.sock` into app containers. Run `docker scout` / `trivy` on every image build. Enable BuildKit and `--secret` mounts so secrets never end up in layers.

---

## 14. VPS hardening

Per CIS Ubuntu 22.04 LTS Benchmark, condensed:

- SSH: `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, key-only (Ed25519). Move SSH off 22 (not security, just noise reduction).
- `ufw default deny incoming`, allow only `22/tcp` (or your SSH port) and `443/tcp`, `80/tcp`.
- `fail2ban` with `sshd` jail (5 fails / 10 min → 1h ban), and a separate jail tailing Caddy access log for repeated 401s on `/api/auth`.
- `unattended-upgrades` on, with `Unattended-Upgrade::Automatic-Reboot "true"` during a maintenance window.
- Non-root user `simplevault` in the `docker` group (be aware: `docker` group ≈ root; mitigated by §13 hardening + no shared tenants).
- Full-disk encryption (LUKS) at provisioning if your provider supports it.
- Optional: encrypted swap via `cryptsetup` / disable swap entirely on small VPS.
- `auditd` rules for `/etc/ssh`, `/etc/sudoers`, `/var/lib/docker`.
- Time sync via `chrony` (HMAC-signed cookies depend on accurate clock).
- Disable IPv6 if unused, otherwise `ufw` rules for v6 too.

---

## 15. Backup pitfalls

**Pitfalls.** Backups dumped to `/backups` on the same disk; nightly cron uses the app's DB password (so app compromise = backup compromise); restores never tested; `pg_dump` via HTTP endpoint with weak auth; backup files world-readable in S3 bucket.

**Recommendation.**
- **`restic`** to an off-host destination (Backblaze B2, Hetzner Storage Box, Wasabi). Restic password is a **separate secret**, stored in 1Password/printed and **NOT on the VPS** — instead, the cron job pulls it from a sealed env file mounted only at backup time, OR backups run from a separate host that pulls from the VPS.
- Database dump pipe directly into restic (`pg_dump | restic backup --stdin`); never write plaintext dump to disk.
- **Weekly off-site copy** via `rclone copy` to a second provider (defense against single-provider account compromise).
- **Monthly restore drill**: spin up `simplevault-staging` container, restore latest snapshot, run smoke tests, tear down. Calendar reminder; failed drill = P1.
- Retention: 7 daily, 4 weekly, 12 monthly.
- `restic check --read-data-subset=10%` weekly to detect bitrot.
- Backup endpoint (if exposed for "download my data"): per-user, encrypted to user's key, rate-limited, 2FA-gated.

---

## 16. Audit log "audit log of audit log"

**Threat.** The operator (you) has DB access. A motivated insider could `UPDATE audit_log SET ... WHERE id = X` to cover up an unauthorized vault read.

**Mitigation.**
- Each audit row contains `prev_hash` = SHA-256 of previous row's canonical serialization. Forms a hash chain. Tampering with row N invalidates all hashes ≥ N+1.
- **Daily Merkle root checkpoint** exported off-machine: cron computes the root of today's chain segment, signs it with an Ed25519 key whose private half is on the operator's hardware token (not on the VPS), commits it to a public-or-private Git repo (GitHub/Codeberg). External witness.
- Optionally publish the daily root to a transparency log (Sigstore Rekor) for free, public, append-only witnessing.
- **Honest scope statement.** This does NOT prevent tampering — the operator can rewrite history before the next checkpoint, then forge a new chain. It does provide **detection** with up to 24h granularity, and creates **non-repudiable evidence** if a checkpoint disagrees with the live chain. For a single-operator self-hosted product, that is the realistic ceiling without bringing in an external trust anchor.
- Document this honestly in the threat model: "operator with DB access can tamper with the last ≤24h of audit logs".

---

## 17. Logout / session termination

**Edge cases.**
- User clicks logout → access cookie cleared, but refresh token row remains valid in DB → attacker who already stole the refresh token still has access.
- Multiple devices: logout on phone does not log out laptop.
- "Log out all sessions" doesn't actually invalidate already-issued JWTs because they're stateless.

**Rules.**
- Logout endpoint: **DELETE refresh token row** + clear cookies + add `jti` of current access token to a short-lived denylist (Redis with TTL = remaining access TTL).
- "Log out all sessions": delete **all** refresh token rows for `user_id`; bump `user.token_epoch` int; embed `epoch` in every access token; verifier rejects tokens with stale epoch.
- **Access token TTL = 15 min** so denylist never grows large.
- Show user a "Active Sessions" page listing refresh-token rows with device fingerprint + last-used + IP + city; allow per-row revoke.
- On password change → invalidate everything (bump epoch + delete refresh tokens), force re-login.

---

## 18. Recovery code pitfalls

**Pitfalls.** Recovery code = master password equivalent. If sent by email = breach if mailbox ever compromised. If stored server-side in plaintext = full recovery on DB leak. Shown once, user closes tab, locked out forever.

**Rules.**
- Recovery code generated client-side at signup (Diceware-ish, 24 chars, ≥128 bits entropy).
- Server stores only `Argon2id(recovery_code)` — verifier hash, never used for crypto.
- The actual key wrap: `recovery_kek = HKDF(recovery_code)`, used to wrap a copy of the user's `vault_master_key`. Only the wrapped blob is on the server.
- **Forced re-display flow:** until the user clicks "I've saved my recovery code" (or downloads the Emergency Kit PDF), every login lands on a "Save your recovery code" interstitial. After 7 days, also email a reminder.
- Single-use: when a recovery code is used to sign in, **invalidate it and force generation of a new one** before the session can be used (recovery code rotation). Old wrapped-key blob deleted; new one written under the new code.
- Never email the code. Never copy to server clipboard. Never log it (audit log records "recovery used", not the code).

---

## 19. "Forgot username" enumeration

**Solution.** Username = email. There is no separate username. "Forgot email" flow = "sorry, contact support". Do not implement a username lookup endpoint at all.

If product later adds usernames distinct from email: recovery requires email + signed magic link click + then displays username. Response on the request screen is always: "If we have a matching account we'll email you" — same body, same status, same timing as password reset (§8).

---

## 20. Side-channels EXPLICITLY out of scope for v1

Documented as **accepted risk**:

- **Spectre/Meltdown** and other CPU microarch leaks on shared VPS host. Mitigation requires bare metal or trusted hypervisor — out of budget. Recommend dedicated VPS plans, not "shared CPU" tiers.
- **RAM dump of running container** by VPS provider or hypervisor escape. Defense requires confidential computing (AMD SEV-SNP, Intel TDX) — out of scope.
- **Traffic analysis** (request size/timing reveals which item was opened). Mitigation would require constant-rate cover traffic + padding — UX/cost prohibitive.
- **Physical access** to the user's unlocked device.
- **Malicious browser extensions** running in the user's profile.
- **Compromise of the user's email** (full account takeover via reset; mitigated partially by recovery code requirement).
- **Nation-state adversary** with TLS-CA coercion or BGP hijack capability.

These are listed in `THREAT_MODEL.md` and surfaced in the security page of the docs so users can make informed choices.

---

## CRITICAL PITFALL CHECKLIST (auditor agents must verify)

1. All vault fields encrypted client-side, including URL/title/tags. No plaintext leakage in DB schema.
2. Single global Argon2id KDF policy enforced server-side; legacy params auto-upgraded on next login.
3. Operator admin actions require hardware-key-bound session, separate from dev machine.
4. Optional but recommended: two-secret model (account_secret) implemented and Emergency Kit generated.
5. Optimistic locking with `version` int + `If-Match` on every mutating endpoint; 409 returns both ciphertexts.
6. JWT verify pins `alg` allowlist; EdDSA keys with `kid` allowlist; tokens in HttpOnly+Secure+SameSite=Strict cookies; never `localStorage`.
7. Access TTL ≤ 15 min; refresh tokens rotated every use with replay detection (revoke family on reuse).
8. Global CSRF guard: double-submit token + Origin/Referer check on every state-changing route.
9. CSP with per-request nonce; no `unsafe-inline`, no `unsafe-eval`, no third-party origins; HSTS preload; frame-ancestors none; base-uri none.
10. Login error messages identical for unknown user vs wrong password vs disabled account.
11. Login always runs Argon2 (dummy hash for missing user) and pads response to a fixed floor (≥350ms).
12. Signup, password reset, "forgot username" use identical responses regardless of account existence.
13. 2FA prompt shown universally after first-factor success (no enumeration of 2FA-enabled users).
14. Note editor stores TipTap JSON only; schema allowlist for nodes/marks; href/src URL scheme allowlist; no `dangerouslySetInnerHTML`; defensive `sanitize-html` at render.
15. Clipboard copy of secrets auto-clears at 30s; clears on tab hide; visible countdown.
16. No `window.addEventListener('message')` without strict origin + payload validation.
17. `pnpm-lock.yaml` committed; CI uses `--frozen-lockfile`; exact-pin security-critical deps; `npm audit signatures` blocks merge; SBOM generated per release.
18. All containers run non-root, read-only FS, `cap_drop: ALL`, `no-new-privileges`, mem/pids limits, pinned image digests; Postgres NOT published; no `docker.sock` mounts; secrets via Docker secrets (not env-in-image).
19. VPS: SSH key-only, root login disabled, `ufw` deny-by-default, `fail2ban`, `unattended-upgrades`, non-root operator user, FDE.
20. Restic backups to off-host destination with separate password not stored on VPS; weekly second-provider copy; monthly restore drill into staging; backup encryption key not derivable by running app.
21. Audit log hash-chained; daily Merkle root signed by off-machine hardware key and committed to external witness (Git/Rekor); honest scope documented.
22. Logout deletes refresh token row + denylists current access `jti`; "logout all" bumps `user.token_epoch`; password change invalidates everything.
23. Recovery code: client-generated, ≥128 bits entropy, Argon2-hashed server-side, wraps a copy of `vault_master_key`; forced save interstitial; single-use with rotation.
24. Username lookup endpoint does not exist; email-only recovery with identical-response screen.
25. Side-channel exclusions documented in `THREAT_MODEL.md` and surfaced to users in `/security` docs page.

---

*Word count: ~2400. Citations: see inline incident names; verify URLs (LastPass blog, OWASP cheatsheets, Bitwarden whitepaper, 1Password whitepaper, Snyk advisory DB) before publication — WebFetch was disabled for this research session.*
