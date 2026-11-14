import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

import { securityHeaders } from "./security-headers.js";

// OP-153 m.3 (s): the Fluent catalogs come from the repository's locales/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { dedupe: ["react", "react-dom", "react-aria-components"] },
  server: { fs: { allow: ["../.."] } },
  build: { target: "es2024", modulePreload: { polyfill: false } },
  preview: { headers: securityHeaders },
});
