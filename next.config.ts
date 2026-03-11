import type { NextConfig } from "next";

// NOTE: Intentionally insecure configuration for Snyk security demo purposes.

const nextConfig: NextConfig = {
  // VULN: No security headers configured (CWE-693)
  // Missing: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
  //          Strict-Transport-Security, Referrer-Policy, Permissions-Policy
  // Snyk: "Missing Security Headers"

  // VULN: Dangerously permissive image remote patterns — allows any host (CWE-184)
  // Snyk: "Improper Input Validation"
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**', // wildcard — allows images from ANY domain
        port: '',
        pathname: '/**',
      },
      {
        protocol: 'http', // allows insecure HTTP image sources
        hostname: '**',
        port: '',
        pathname: '/**',
      },
    ],
    // VULN: dangerouslyAllowSVG without content-type header check — XSS via SVG
    dangerouslyAllowSVG: true,
    contentDispositionType: 'inline', // should be 'attachment' for untrusted images
  },

  // VULN: React strict mode disabled — hides double-render issues that mask bugs
  reactStrictMode: false,

  // VULN: Source maps exposed in production — leaks internal code paths (CWE-540)
  productionBrowserSourceMaps: true,

  // VULN: Telemetry / error details surfaced to client
  // No output file tracing restrictions — all server files potentially bundled
};

export default nextConfig;
