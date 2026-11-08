import { defineConfig, devices } from "@playwright/test";

const port = 4173;
const ci = process.env["CI"] !== undefined;
// OP-153 m.3 (gg): the live project runs against a running local deployment's management listener
const live = process.env["ACCESS_LIVE_CONSOLE_ORIGIN"] ?? "https://access-server.local:9443";
const realm = process.env["ACCESS_LIVE_ORIGIN"] ?? "https://access-server:8443";

export default defineConfig({
  // SA-59
  retries: 0,
  forbidOnly: ci,
  fullyParallel: true,
  reporter: ci ? [["list"], ["html", { open: "never" }]] : "list",
  snapshotPathTemplate: "{testDir}/__screenshots__/{testFilePath}/{arg}-{platform}{ext}",
  use: { trace: "retain-on-failure" },
  projects: [
    {
      name: "chromium",
      testDir: "./e2e",
      testIgnore: "live/**",
      use: { ...devices["Desktop Chrome"], baseURL: `http://127.0.0.1:${String(port)}` },
    },
    {
      name: "live",
      testDir: "./e2e/live",
      grep: /@live/,
      use: {
        ...devices["Desktop Chrome"],
        baseURL: live,
        ignoreHTTPSErrors: true,
        launchOptions: {
          args: [
            `--host-resolver-rules=MAP ${new URL(live).hostname} 127.0.0.1, MAP ${new URL(realm).hostname} 127.0.0.1`,
          ],
        },
      },
    },
  ],
  ...(process.argv.includes("--project=live")
    ? {}
    : {
        webServer: {
          command: `npx vite build && npx vite preview --host 127.0.0.1 --port ${String(port)} --strictPort`,
          url: `http://127.0.0.1:${String(port)}/console/`,
          reuseExistingServer: false,
        },
      }),
});
