// IDP-30, B22, OP-156 m.3 (l), (m): the console's forward-auth proxies over mocked management
// answers; the check's rules are the server's (bins/access-server bootstrap proxy walkthroughs).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/proxies", {
    items: [
      {
        name: "wiki",
        engine: "envoy",
        host: "wiki.example.com",
        upstream: "http://127.0.0.1:8080",
        status: "live",
        plain_headers: false,
        decision_cache_s: 30,
        routes: ["/"],
      },
      {
        name: "old",
        engine: "caddy",
        host: "old.example.com",
        upstream: null,
        status: "retired",
        plain_headers: false,
        decision_cache_s: 30,
        routes: ["/"],
      },
    ],
  });
});

// OP-156 m.3 (l), (m)
test("proxies are registered and retired only through signed changes", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/proxy");
  await expect(page.getByRole("heading", { level: 2, name: "Application proxies" })).toBeVisible();
  const list = page.getByTestId("proxies");
  await expect(list).toContainText("wiki.example.com");
  await expect(list).toContainText("Decisions reused for at most 30 s");
  await expect(list.getByRole("button", { name: "Retire old" })).toHaveCount(0);
  await expect(page.getByTestId("proxy-plain-note")).toBeVisible();
  expect(bff.writes).toEqual([]);

  const register = page.getByRole("button", { name: "Register proxy" });
  await expect(register).toBeDisabled();
  await page.getByLabel("Name", { exact: true }).fill("grafana");
  await page.getByLabel("Engine").selectOption("caddy");
  await page.getByLabel("Application host").fill("grafana.example.com");
  await page.getByLabel("Sign-in client").fill("client-1");
  await page.getByLabel("Proxy certificate thumbprint").fill("A".repeat(43));
  await page.getByLabel("Action namespace").fill("work");
  await page.getByLabel("Action name", { exact: true }).fill("use");
  await page.getByLabel("Action schema digest").fill("B".repeat(43));
  await page.getByLabel("Resource namespace").fill("apps");
  await page.getByLabel("Path patterns").fill("/, /admin");
  await register.click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  await list.getByRole("button", { name: "Turn on plain headers for wiki" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  await list.getByRole("button", { name: "Retire wiki" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["POST", "realms/acme/proxies"],
    ["PUT", "realms/acme/proxies/wiki/plain-headers"],
    ["POST", "realms/acme/proxies/wiki/retire"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({
    name: "grafana",
    engine: "caddy",
    host: "grafana.example.com",
    action: { namespace: "work", name: "use", major: 1 },
    namespace: "apps",
    routes: ["/", "/admin"],
  });
  expect(bff.writes[0]?.body).not.toHaveProperty("upstream");
  expect(bff.writes[1]?.body).toMatchObject({ enabled: true });

  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});
