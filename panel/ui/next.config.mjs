/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  distDir: ".next",
  images: {
    unoptimized: true,
  },
  poweredByHeader: false,
  reactStrictMode: true,
  trailingSlash: false,
};

export default nextConfig;
