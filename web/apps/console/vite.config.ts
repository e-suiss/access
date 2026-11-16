import { fileURLToPath } from "node:url";
import babel from "@rolldown/plugin-babel";
import tailwindcss from "@tailwindcss/vite";
import react, { reactCompilerPreset } from "@vitejs/plugin-react";

import { defineConfig } from "vite";

import { securityHeaders } from "./security-headers.js";

// TN-128: served by the BFF under /console/ on the management listener
export default defineConfig({
  base: "/console/",
  // OP-159 m.46 (c)
  plugins: [react(), babel({ presets: [reactCompilerPreset()] }), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
    dedupe: ["react", "react-dom", "@base-ui/react"],
  },
  server: { fs: { allow: ["../../.."] } },
  build: { target: "es2024" },
  preview: { headers: securityHeaders },
});
