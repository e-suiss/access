import { defineConfig, devices } from "@playwright/test";

const port = 4173;
const ci = process.env["CI"] !== undefined;

export default defineConfig({
  testDir: "./e2e",
  // SA-59
  retries: 0,
  forbidOnly: ci,
  fullyParallel: true,
  reporter: ci ? [["list"], ["html", { open: "never" }]] : "list",
  snapshotPathTemplate: "{testDir}/__screenshots__/{testFilePath}/{arg}-{platform}{ext}",
  use: {
    baseURL: `http://127.0.0.1:${String(port)}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `npx vite build && npx vite preview --host 127.0.0.1 --port ${String(port)} --strictPort`,
    url: `http://127.0.0.1:${String(port)}`,
    reuseExistingServer: false,
  },
});
