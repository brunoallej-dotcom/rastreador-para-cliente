import type { NextConfig } from 'next';

// Security headers entram na Onda 1.
const nextConfig: NextConfig = {
  poweredByHeader: false,
  reactStrictMode: true,
};

export default nextConfig;
