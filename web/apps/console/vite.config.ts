import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

import { defineConfig } from "vite";

import { securityHeaders } from "./security-headers.js";

// TN-128: served by the BFF under /console/ on the management listener
export default defineConfig({
  base: "/console/",
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
    dedupe: ["react", "react-dom", "@base-ui/react"],
  },
  server: { fs: { allow: ["../../.."] } },
  build: { target: "es2024" },
  preview: { headers: securityHeaders },
});
