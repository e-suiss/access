// IDP-32, OP-156 m.3 (o): the console's SSH certificate authority over mocked management
// answers; the CA's rules are the server's (bins/access-server bootstrap SSH walkthroughs).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

test.beforeEach(async ({ context, bff }) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/ssh-host-groups", {
    items: [
      { name: "prod-web", description: "Web servers", status: "live", version: 1 },
      { name: "old-db", description: "", status: "retired", version: 2 },
    ],
  });
});

// OP-156 m.3 (o)
test("the CA and its server groups change only through signed changes", async ({ page, bff }) => {
  await open(page, bff, "/console/admin/ssh");
  await expect(page.getByRole("heading", { level: 2, name: "SSH access" })).toBeVisible();
  await expect(page.getByTestId("ssh-ca-url")).toHaveText("/realms/acme/ssh/ca.pub");
  await expect(page.getByTestId("ssh-krl-url")).toHaveText("/realms/acme/ssh/krl");
  await expect(page.getByTestId("ssh-sshd-config")).toContainText(
    "TrustedUserCAKeys /etc/ssh/access-ca.pub",
  );
  await expect(page.getByTestId("ssh-replace-warning")).toBeVisible();
  const groups = page.getByTestId("ssh-groups");
  await expect(groups).toContainText("prod-web");
  await expect(groups.getByRole("button", { name: "Retire old-db" })).toHaveCount(0);
  await expect(page.getByTestId("ssh-certificates-note")).toContainText("ssh.certificate_issued");
  expect(bff.writes).toEqual([]);

  await page.getByRole("button", { name: "Turn on" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  await page.getByLabel("Name", { exact: true }).fill("staging");
  await page.getByLabel("Description").fill("Staging");
  await page.getByRole("button", { name: "Register", exact: true }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  await groups.getByRole("button", { name: "Retire prod-web" }).click();
  await page
    .getByRole("dialog", { name: "Review and sign" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByRole("status")).toContainText("Recorded as change");

  expect(bff.writes.map((w) => [w.method, w.path])).toEqual([
    ["PUT", "realms/acme/settings/ssh-ca"],
    ["POST", "realms/acme/ssh-host-groups"],
    ["POST", "realms/acme/ssh-host-groups/prod-web/retire"],
  ]);
  expect(bff.writes[0]?.body).toMatchObject({ enabled: true });
  expect(bff.writes[1]?.body).toMatchObject({ name: "staging", description: "Staging" });

  const result = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(result.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});
