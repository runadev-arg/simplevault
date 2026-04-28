import { NextResponse, type NextRequest } from "next/server";

import { SECURITY_HEADERS, buildCsp } from "./lib/csp";

export function middleware(request: NextRequest): NextResponse {
  // Generate per-request nonce. Web Crypto in Edge runtime.
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const nonce = btoa(bin);

  // Propagate nonce to server components via request header
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);

  const response = NextResponse.next({ request: { headers: requestHeaders } });

  // CSP with the nonce
  response.headers.set("Content-Security-Policy", buildCsp(nonce));
  // Other static security headers
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
    response.headers.set(k, v);
  }
  return response;
}

export const config = {
  matcher: [
    // Run on every request EXCEPT static assets
    "/((?!_next/static|_next/image|favicon.ico|robots.txt|sitemap.xml).*)",
  ],
};
