import { join } from "node:path";

import type { NextConfig } from "next";

import { apiRewriteOriginFrom } from "./src/config/api";

const apiOrigin = apiRewriteOriginFrom(process.env);

const nextConfig: NextConfig = {
  output: "standalone",
  /* Stated rather than inferred, so the traced root is the same everywhere. */
  outputFileTracingRoot: join(import.meta.dirname, "..", ".."),
  reactStrictMode: true,
  /* Development only: the loopback address the local stack serves on. */
  allowedDevOrigins: ["127.0.0.1"],
  poweredByHeader: false,
  /* This repository writes its own agent instructions; the framework must not. */
  agentRules: false,
  /*
    The browser sees one origin. Production routing belongs to the edge, so the
    rewrite is installed only when a local internal origin is configured.
  */
  ...(apiOrigin
    ? {
        rewrites: async () => [{ source: "/api/:path*", destination: `${apiOrigin}/api/:path*` }],
      }
    : {}),
};

export default nextConfig;
