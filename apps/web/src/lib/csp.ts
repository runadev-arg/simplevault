export function buildCsp(nonce: string): string {
  // Allow XHR/fetch to the API origin (configured via NEXT_PUBLIC_API_URL).
  // Falls back to same-origin only.
  const apiUrl = process.env.NEXT_PUBLIC_API_URL ?? "";
  const apiOrigin = (() => {
    try {
      return apiUrl ? new URL(apiUrl).origin : "";
    } catch {
      return "";
    }
  })();
  const connectSrc = ["'self'"];
  if (apiOrigin && apiOrigin !== "null") connectSrc.push(apiOrigin);

  const directives: Record<string, string[]> = {
    "default-src": ["'self'"],
    // 'wasm-unsafe-eval' is required for libsodium-wrappers-sumo (WASM
    // compiled at runtime from the bundled .wasm). Does NOT relax JS eval.
    "script-src": ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'", "'wasm-unsafe-eval'"],
    "script-src-elem": ["'self'", `'nonce-${nonce}'`, "'strict-dynamic'"],
    "style-src": ["'self'", `'nonce-${nonce}'`],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'"],
    "connect-src": connectSrc,
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
    "frame-src": ["'none'"],
    "object-src": ["'none'"],
    "base-uri": ["'none'"],
    "manifest-src": ["'self'"],
    "upgrade-insecure-requests": [],
  };
  return Object.entries(directives)
    .map(([k, v]) => (v.length === 0 ? k : `${k} ${v.join(" ")}`))
    .join("; ");
}

export const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Permissions-Policy":
    "geolocation=(), microphone=(), camera=(), payment=(), usb=(), interest-cohort=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "X-DNS-Prefetch-Control": "off",
} as const;
