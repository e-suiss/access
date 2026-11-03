import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

import { securityHeaders } from "./security-headers.js";

export default defineConfig({
  plugins: [react()],
  build: { target: "es2024", modulePreload: { polyfill: false } },
  preview: { headers: securityHeaders },
});
