import type { NextConfig } from "next";

// Relaxed CSP for the public blog only: AutoSEO articles embed external CDN
// images in content_html, so img-src must allow https. The landing page keeps
// Next's defaults (no CSP header here). Scoped to /blog and /blog/* exactly.
const BLOG_CSP =
  "default-src 'self'; " +
  "img-src 'self' https: data:; " +
  "style-src 'self' 'unsafe-inline'; " +
  "script-src 'self' 'unsafe-inline'; " +
  "frame-ancestors 'none'; " +
  "base-uri 'self'";

const nextConfig: NextConfig = {
  // Standalone output → small runner image (node server.js) for App Platform.
  output: "standalone",
  // Pin the workspace root to this dir — a stray ~/yarn.lock otherwise makes
  // Next infer the home dir as root, which breaks standalone file tracing.
  turbopack: { root: import.meta.dirname },
  outputFileTracingRoot: import.meta.dirname,
  async headers() {
    return [
      {
        source: "/blog",
        headers: [{ key: "Content-Security-Policy", value: BLOG_CSP }],
      },
      {
        source: "/blog/:slug*",
        headers: [{ key: "Content-Security-Policy", value: BLOG_CSP }],
      },
    ];
  },
};

export default nextConfig;
