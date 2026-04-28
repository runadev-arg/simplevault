/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "standalone",
  reactStrictMode: true,
  poweredByHeader: false,
  experimental: {
    typedRoutes: true,
  },
  // No images config yet (no images in v1 pages); revisit Phase 05.
};

export default nextConfig;
