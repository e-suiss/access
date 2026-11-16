import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";

import { securityHeaders } from "./security-headers.js";

// OP-153 m.3 (w): served by the account BFF under /account on the environment's public listener; the
// Fluent catalogs come from the repository's locales/
export default defineConfig({
  base: "/account/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
    dedupe: ["react", "react-dom", "@base-ui/react"],
  },
  server: { fs: { allow: ["../../.."] } },
  build: { target: "es2024", modulePreload: { polyfill: false } },
  preview: { headers: securityHeaders },
});
