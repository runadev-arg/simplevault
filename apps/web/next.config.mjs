import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  // In a monorepo, Next must trace files starting from the repo root so the
  // standalone output bundles workspace deps (@simplevault/shared) correctly.
  outputFileTracingRoot: path.join(__dirname, "../../"),
  reactStrictMode: true,
  poweredByHeader: false,
  typedRoutes: true,
  // No images config yet (no images in v1 pages); revisit Phase 05.
};

export default nextConfig;
