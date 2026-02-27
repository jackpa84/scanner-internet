/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    const backend = process.env.API_BACKEND_URL || "http://localhost:5001";
    return [
      { source: "/api/:path*", destination: `${backend}/api/:path*` },
    ];
  },
  webpack: (config) => {
    if (process.env.WATCHPACK_POLLING === "true") {
      config.watchOptions = {
        poll: 1000,
        aggregateTimeout: 300,
      };
    }
    return config;
  },
};

export default nextConfig;
