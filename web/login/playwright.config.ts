import { defineConfig, devices } from "@playwright/test";

const port = 4174;
const ci = process.env["CI"] !== undefined;

// OP-146 m.4 (a)
export default defineConfig({
  testDir: "./e2e",
  // SA-59
  retries: 0,
  forbidOnly: ci,
  fullyParallel: true,
  reporter: ci ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: `http://acme.localhost:${String(port)}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `npx vite build && npx vite preview --host 127.0.0.1 --port ${String(port)} --strictPort`,
    url: `http://127.0.0.1:${String(port)}`,
    reuseExistingServer: false,
  },
});
