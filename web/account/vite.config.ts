import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

import { securityHeaders } from "./security-headers.js";

// OP-153 m.3 (w): served by the account BFF under /account on the realm's public listener; the
// Fluent catalogs come from the repository's locales/
export default defineConfig({
  base: "/account/",
  plugins: [react()],
  resolve: { dedupe: ["react", "react-dom"] },
  server: { fs: { allow: ["../.."] } },
  build: { target: "es2024", modulePreload: { polyfill: false } },
  preview: { headers: securityHeaders },
});
