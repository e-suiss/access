// §8.12, §8.17.9.7, §13.6, OP-158 m.3 (m): Audit ▸ Recovery and handover over a mocked management
// answer; the history is the server's (bins/access-server durability recovery tests).
import AxeBuilder from "@axe-core/playwright";

import { BASE, open } from "./data.js";
import { expect, test } from "./fixtures.js";

// §13.6 S7, RR-5, Ek B 5748
test('a domain without a recovery entry says "Recovery not available"', async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/recovery", {
    realm: "acme",
    recovery: "not_available",
    recovery_reason: "no-recovery-entry",
    history: [],
  });
  await open(page, bff, "/console/audit/recovery");
  await expect(page.getByTestId("recovery-not-available")).toContainText("Recovery not available");
  await expect(page.getByTestId("recovery-banner")).toHaveCount(0);
  expect(bff.writes).toEqual([]);
});

// §8.13, §8.17.9.7, E20, Ek B 5882, 6031, 6032
test("after a forced recovery the banner says what may be lost and the history lists it", async ({
  page,
  context,
  bff,
}) => {
  await bff.signIn(context, BASE);
  bff.admin.set("realms/acme/recovery", {
    realm: "acme",
    recovery: "available",
    recovery_threshold: { k: 2, n: 3 },
    held_on: "device",
    history: [
      { kind: "handover", position: "40", at: "2026-11-01T09:00:00Z" },
      {
        kind: "recovered",
        position: "120",
        at: "2026-11-10T12:00:00Z",
        lost_after: "2026-11-10T11:02:00Z",
      },
    ],
  });
  await open(page, bff, "/console/audit/recovery");
  const banner = page.getByTestId("recovery-banner");
  await expect(banner).toContainText("Recovered from previous provider at record position 120");
  await expect(banner).toContainText("revoke it again");
  await expect(page.getByTestId("recovery-available")).toContainText("2 of 3");
  await expect(page.locator('[data-testid="recovery-entry"][data-kind="handover"]')).toContainText(
    "record position 40",
  );
  expect(bff.writes).toEqual([]);
  const a11y = await new AxeBuilder({ page }).include("main").analyze();
  expect(a11y.violations).toEqual([]);
});
