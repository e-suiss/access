// OP-157 m.3 (f), §8.16, TN-137, XI-7, XI-17, SI-21
import type { Page } from "@playwright/test";

import { expect, test } from "./fixtures.js";
import { type AccountMock, PARTY } from "./mock.js";

test.beforeEach(async ({ bff, context, baseURL }) => {
  await bff.signIn(context, baseURL ?? "");
});

async function device(page: Page, bff: AccountMock): Promise<void> {
  await page.goto("/account/authority");
  await page.getByRole("button", { name: "Set up this device" }).click();
  await page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Sign" })
    .click();
  await expect(page.getByTestId("hub")).toBeVisible();
  bff.instanceKid = await page.evaluate(
    () =>
      new Promise<string>((resolve, reject) => {
        const open = indexedDB.open("access-account", 1);
        open.onsuccess = () => {
          const keys = open.result.transaction("instances").objectStore("instances").getAllKeys();
          keys.onsuccess = () => {
            resolve((keys.result[0] as string).split("/").pop() ?? "");
          };
          keys.onerror = () => {
            reject(new Error("keys"));
          };
        };
      }),
  );
}

const sign = (page: Page) =>
  page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Sign" })
    .click();

test("the person reads the exact terms, gives access with their device and revokes it", async ({
  page,
  bff,
}) => {
  bff.supportRequests = [bff.supportRequest("spr_1")];
  await device(page, bff);
  await page.goto("/account/support");
  const sheet = page.getByRole("dialog", { name: "Give Acme Support access" });
  await expect(sheet).toContainText(
    "view your account settings · case 4411 · for 60 minutes · can't change sign-in methods, payments or email · can't pass on",
  );
  await expect(sheet.getByRole("button", { name: /approve/i })).toHaveCount(0);
  await sheet.getByRole("button", { name: "Give access", exact: true }).click();
  await sign(page);
  const row = page.getByTestId("support-active");
  await expect(row).toContainText("Mehmet Y. (Acme Support) · case 4411");
  const give = bff.seen.find((s) => s.path.endsWith("/give"));
  expect(typeof give?.body["ais"]).toBe("string");
  expect(give?.body["payload"]).toBe(Buffer.alloc(8, 9).toString("base64url"));
  await row.getByRole("button", { name: "Revoke" }).click();
  await sign(page);
  await expect(page.getByTestId("support-past")).toContainText("You revoked support access");
});

test("nothing is signed if the person declines or cancels", async ({ page, bff }) => {
  bff.supportRequests = [bff.supportRequest("spr_1")];
  await device(page, bff);
  await page.goto("/account/support");
  await page.getByRole("button", { name: "Give access", exact: true }).click();
  await page
    .getByRole("dialog", { name: "Check what you're signing" })
    .getByRole("button", { name: "Cancel" })
    .click();
  expect(bff.seen.some((s) => s.path.endsWith("/give"))).toBe(false);
  await page.getByRole("button", { name: "Don't give access" }).click();
  await expect(page.getByTestId("said")).toHaveText("You didn't give access. Nothing changed.");
  await expect(page.getByTestId("support-request")).toHaveCount(0);
});

test("Block support access is the person's own setting", async ({ page, bff }) => {
  await device(page, bff);
  await page.goto("/account/support");
  await expect(page.getByTestId("support-access")).toContainText(
    "No one has support access to your account.",
  );
  await page.getByTestId("support-block").click();
  await expect(page.getByText("Support teams can't ask for access")).toBeVisible();
  expect(bff.supportBlocked).toBe(true);
});

test("a use of support access names the operator, never the person", async ({ page, bff }) => {
  bff.supportGiven = [
    {
      id: "spr_1",
      state: "active",
      operator: "Mehmet Y.",
      organization: "Acme Support",
      case: "4411",
      what: "view your account settings",
      minutes: 60,
      read_only: true,
      until: "2030-01-02T03:04:05.000Z",
      basis: { holding: { grant: "Z3JhbnQ", holder: "b3A", since: 7 } },
    },
  ];
  await device(page, bff);
  bff.searches.set("activity", [
    {
      type: "use",
      pos: 9,
      at: 1_800_000_000_000,
      by_viewer: false,
      capacity: { for: PARTY },
      basis: { grant: "Z3JhbnQ" },
      exercise: "ZXhlcg",
      instance: "aW4",
      reports: { attested: [] },
    },
  ]);
  await page.goto("/account/activity");
  const use = page.getByTestId("use");
  await expect(use).toContainText(
    "Viewed your account — by Mehmet Y. (Acme Support) on your behalf",
  );
  await expect(use).not.toContainText("You acted");
});
