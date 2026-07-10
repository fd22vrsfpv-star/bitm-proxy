import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    // Emit hashed SPA files under /proxy-assets/ instead of the default
    // /assets/, so this app can coexist on an nginx vhost that already
    // owns /assets/ (e.g. a sibling SPA).
    assetsDir: "proxy-assets",
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8091",
        ws: true,
      },
    },
  },
});
