import type { NextConfig } from 'next';
// Relative import on purpose: the `@/` alias is not available when Next loads this file.
import { SECURITY_HEADERS } from './src/shared/http/security-headers';

const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
  // SEC-14 on EVERY path, so responses Next produces itself (404, 405, OPTIONS) carry them too.
  // `withRoute` sets the same headers (plus X-Request-Id) on every API response.
  headers() {
    return Promise.resolve([
      {
        source: '/:path*',
        headers: Object.entries(SECURITY_HEADERS).map(([key, value]) => ({ key, value })),
      },
    ]);
  },
};

export default nextConfig;
