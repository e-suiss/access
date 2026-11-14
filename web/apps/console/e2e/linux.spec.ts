// IDP-32, OP-156 m.3 (p): the console's Linux client hosts over mocked management answers; the
// rules are the server's (bins/access-server bootstrap Linux walkthrough).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

const CERT = "x".repeat(43);

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/linux-hosts", {
    items: [
      {
        name: "web-1",
        host_group: "prod-web",
        certificate: CERT,
        sudo_ct: 2,
        nss_ttl_s: 43200,
        console_ttl_s: 28800,
        break_glass: false,
        status: "live",
      },
      {
        name: "old-1",
        host_group: "prod-web",
        certificate: CERT,
        sudo_ct: 2,
        nss_ttl_s: 0,
        console_ttl_s: 0,
        break_glass: false,
        status: "retired",
      },
    ],
  });
});

// OP-156 m.3 (p)
test("hosts change only through signed changes", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/linux");
  await expect(page.getByRole("heading", { level: 2, name: "Linux computers" })).toBeVisible();
  const hosts = page.getByTestId("linux-hosts");
  await expect(hosts).toContainText("users known for 12 h, sign-in reused for 8 h");
  await expect(hosts).toContainText("security key required (CT2), never offline");
  await expect(hosts.getByRole("button", { name: "Retire old-1" })).toHaveCount(0);
  await expect(page.getByTestId("linux-nsswitch")).toContainText("passwd: files access");
  expect(bff.writes).toEqual([]);

  await hosts.getByRole("button", { name: "Allow emergency access on web-1" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  await page.getByLabel("Computer name").fill("web-2");
  await page.getByLabel("Server group").fill("prod-web");
  await page.getByLabel("Certificate fingerprint").fill(CERT);
  await page.getByRole("button", { name: "Register", exact: true }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["PUT", "realms/acme/linux-hosts/web-1/break-glass-policy"],
    ["POST", "realms/acme/linux-hosts"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({ enabled: true });
  expect(bff.writes[1]?.body).toMatchObject({ name: "web-2", host_group: "prod-web" });

  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});
