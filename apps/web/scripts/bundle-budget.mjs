#!/usr/bin/env node
// Plan 04-07 (T2): bundle-budget regression guard.
//
// Two complementary checks:
//  1. Global initial-JS guard — no chunk referenced from `rootMainFiles` (the
//     scripts that load on EVERY app-router page) may contain the strings
//     "zxcvbn" or "language-en". This is the pragmatic fallback the plan calls
//     out: per-route attribution in Next 15 is fiddly, but if zxcvbn ever
//     leaks into the shared graph, every route pays for it — exactly the
//     regression we want to surface.
//  2. Initial-JS gzipped size budget — the rootMain chunks summed and gzipped
//     must stay under 250 KiB. This catches "we accidentally added a 600 KiB
//     dictionary to the shared bundle" via raw weight even if the string-grep
//     somehow passes.
//
// Per-route Cypress assertion (zxcvbn chunk fetched on /credential/new but
// NOT on /vault) lives in Plan 04-12.
import { readFile, stat } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import path from "node:path";

const WEB_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const NEXT_ROOT = path.join(WEB_ROOT, ".next");
const APP_BUILD_MANIFEST = path.join(NEXT_ROOT, "app-build-manifest.json");
const BUILD_MANIFEST = path.join(NEXT_ROOT, "build-manifest.json");

const FORBIDDEN_IN_INITIAL = ["zxcvbn", "language-en"];
const INITIAL_JS_MAX_BYTES = 250 * 1024; // 250 KiB gzipped

async function exists(p) {
  try {
    await stat(p);
    return true;
  } catch {
    return false;
  }
}

async function readJson(p) {
  return JSON.parse(await readFile(p, "utf8"));
}

async function loadInitialChunks() {
  // Prefer the app-router build manifest if present (Next 13+ app dir).
  const root = NEXT_ROOT;
  let chunks = new Set();
  if (await exists(APP_BUILD_MANIFEST)) {
    const m = await readJson(APP_BUILD_MANIFEST);
    for (const f of m.rootMainFiles ?? []) chunks.add(f);
    // The shared layout chunks live under pages: { "/_layout": [...] } in some
    // Next versions. Grab everything under "pages" too — initial JS for any
    // page is a superset of the rootMainFiles.
    for (const list of Object.values(m.pages ?? {})) for (const f of list) chunks.add(f);
  }
  if (await exists(BUILD_MANIFEST)) {
    const m = await readJson(BUILD_MANIFEST);
    for (const f of m.rootMainFiles ?? []) chunks.add(f);
  }
  return [...chunks].map((rel) => path.join(root, rel));
}

async function main() {
  if (!(await exists(NEXT_ROOT))) {
    console.error("[bundle-budget] No .next directory; run `pnpm build` first.");
    process.exit(2);
  }
  const chunks = await loadInitialChunks();
  if (chunks.length === 0) {
    console.error("[bundle-budget] No initial chunks discovered in build manifest.");
    process.exit(2);
  }

  const violations = [];
  let totalRaw = 0;
  let totalGzip = 0;
  for (const chunk of chunks) {
    if (!(await exists(chunk))) continue;
    const buf = await readFile(chunk);
    totalRaw += buf.byteLength;
    totalGzip += gzipSync(buf).byteLength;
    const text = buf.toString("utf8");
    for (const needle of FORBIDDEN_IN_INITIAL) {
      if (text.includes(needle)) {
        violations.push(`  - ${path.relative(WEB_ROOT, chunk)} contains forbidden token "${needle}"`);
      }
    }
  }

  console.log(
    `[bundle-budget] initial chunks: ${chunks.length}, raw=${(totalRaw / 1024).toFixed(1)} KiB, gzip=${(totalGzip / 1024).toFixed(1)} KiB`,
  );

  let failed = false;
  if (violations.length > 0) {
    failed = true;
    console.error("[bundle-budget] FORBIDDEN tokens in initial bundle:");
    for (const v of violations) console.error(v);
  }
  if (totalGzip > INITIAL_JS_MAX_BYTES) {
    failed = true;
    console.error(
      `[bundle-budget] initial JS gzipped ${(totalGzip / 1024).toFixed(1)} KiB exceeds budget ${(INITIAL_JS_MAX_BYTES / 1024).toFixed(0)} KiB`,
    );
  }
  if (failed) {
    process.exit(1);
  }
  console.log("[bundle-budget] OK");
}

await main();
