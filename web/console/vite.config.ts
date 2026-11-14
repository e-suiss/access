import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

import { securityHeaders } from "./security-headers.js";

// TN-128: served by the BFF under /console/ on the management listener
export default defineConfig({
  base: "/console/",
  plugins: [react(), tailwindcss()],
  resolve: { dedupe: ["react", "react-dom", "react-aria-components"] },
  server: { fs: { allow: ["../.."] } },
  build: { target: "es2024" },
  preview: { headers: securityHeaders },
});
