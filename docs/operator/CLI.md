# SimpleVault — Operator CLI

The operator CLI ships with the repo and is bundled into the `apps/api` Docker
image (see Phase 01 Plan 06 `pnpm deploy`). From the repo root:

```sh
pnpm cli --help
pnpm cli invite create --email user@example.com [--ttl-days 7]
pnpm cli argon2 calibrate
```

In Dokploy, run it from the api container shell:

```sh
node /app/apps/cli/dist/main.js invite create --email user@example.com
node /app/apps/cli/dist/main.js argon2 calibrate
```

## `invite create`

Issues a single-use, HMAC-bound invite code and prints it to stdout ONCE.

- Required env: `DATABASE_URL`, `SERVER_INVITE_SECRET` (≥ 32 bytes)
- Flow:
  1. Generate 16 random bytes → Crockford base32 (no I/L/O/U) → hyphenated
     every 4 chars → `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XX`.
  2. Compute `code_hash = HMAC-SHA256(SERVER_INVITE_SECRET, raw_code_bytes)`.
  3. INSERT into `invite_codes` (`email` lowercased, `expires_at = now + ttl`,
     default 7 days, override with `--ttl-days N` or `--expires-in 14d`).
  4. Print the raw code to stdout; nothing logged anywhere else.
- Fail-fast: missing env → exit 2 with a clear stderr error.

The operator hand-delivers the code via Signal / in-person / their own email
client. **The code is shown only once** — re-issue if lost.

## `argon2 calibrate`

Calibrates Argon2id wall-time to ~750ms on the host where it runs and prints a
copy-paste-ready Dokploy env-var snippet:

```
ARGON2_MEMORY_KIB=<value>
ARGON2_ITERATIONS=<value>
ARGON2_PARALLELISM=1
```

Run this **once** on the production VPS before going live, then paste the
snippet into Dokploy's encrypted env-var UI for the api service.

The CLI warns if discovered params are at or below the conservative floor
(`m=19456, t=2, p=1`) — that means the VPS is too underpowered for production
and the operator should pick beefier hardware.

## Env-var summary

| Var                        | Required by              | Generate                     |
| -------------------------- | ------------------------ | ---------------------------- |
| `DATABASE_URL`             | both subcommands         | provided by Dokploy PG       |
| `SERVER_INVITE_SECRET`     | `invite create`, signup  | `openssl rand -base64 32`    |
| `ARGON2_MEMORY_KIB`        | api (KDF)                | `pnpm cli argon2 calibrate`  |
| `ARGON2_ITERATIONS`        | api (KDF)                | `pnpm cli argon2 calibrate`  |
| `ARGON2_PARALLELISM`       | api (KDF)                | `pnpm cli argon2 calibrate`  |

Phase 12's runbook (`DOKPLOY-DEPLOY.md`) will round out the operational story.
