/**
 * Access JWT — IN-MEMORY ONLY.
 *
 * INVARIANTS (LOAD-BEARING):
 *   - NEVER write the access token to localStorage / sessionStorage /
 *     IndexedDB / cookies / any persistent surface. It lives in JS heap
 *     for the lifetime of the SPA tab and is wiped on logout / refresh
 *     reuse / expiry.
 *   - The refresh token NEVER passes through this module — it lives only
 *     in the `__Host-refresh` HttpOnly cookie set by the API.
 *
 * Stores `{accessToken, expiresAt}` plus a small set of subscribers so
 * React contexts / hooks can react to changes without prop-drilling.
 */

let _accessToken: string | null = null;
let _expiresAt: number = 0;

type Listener = () => void;
const _listeners = new Set<Listener>();

function emit(): void {
  for (const fn of _listeners) {
    try {
      fn();
    } catch {
      // listener errors must not break other listeners
    }
  }
}

/**
 * Decode the `exp` claim from a JWT (no signature verification — server
 * already verifies on every protected call; here we only need the timing
 * to schedule auto-refresh).
 *
 * Returns seconds-since-epoch, or 0 if unparseable.
 */
function decodeExpSeconds(jwt: string): number {
  try {
    const parts = jwt.split(".");
    if (parts.length < 2) return 0;
    const payloadB64 = parts[1];
    if (payloadB64 === undefined) return 0;
    // base64url -> base64
    const b64 = payloadB64.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    const json = atob(b64 + pad);
    const obj = JSON.parse(json) as { exp?: number };
    return typeof obj.exp === "number" ? obj.exp : 0;
  } catch {
    return 0;
  }
}

export const accessTokenStore = {
  /** Set the access token + derive `expiresAt` from its `exp` claim. */
  set(jwt: string, expiresInSec?: number): void {
    _accessToken = jwt;
    if (typeof expiresInSec === "number") {
      _expiresAt = Date.now() + expiresInSec * 1000;
    } else {
      const expSec = decodeExpSeconds(jwt);
      _expiresAt = expSec > 0 ? expSec * 1000 : Date.now() + 15 * 60 * 1000;
    }
    emit();
  },

  /** Returns the token only if still un-expired. */
  get(): string | null {
    if (_accessToken === null) return null;
    if (_expiresAt <= Date.now()) return null;
    return _accessToken;
  },

  /** Raw read — even if expired. Used by the refresh hook to detect "had a token". */
  peek(): string | null {
    return _accessToken;
  },

  expiresAt(): number {
    return _expiresAt;
  },

  /** Drop the token. Idempotent. */
  wipe(): void {
    if (_accessToken === null && _expiresAt === 0) return;
    _accessToken = null;
    _expiresAt = 0;
    emit();
  },

  subscribe(fn: Listener): () => void {
    _listeners.add(fn);
    return () => _listeners.delete(fn);
  },
};
