// RFC 8628 §3.3, OP-154 m.3 (p), TN-35: the verification page reads which app asks, for what and
// from where, before the person approves; every wrong code reads the same.
import { expect, test } from "./fixtures.js";

function device(mock: import("./mock.js").LoginMock) {
  mock.json.set("POST /v1/device/preview", (body) =>
    (body as { user_code?: string }).user_code === "BCDF-GHJZ"
      ? {
          status: 200,
          body: {
            client: "Living room TV",
            scopes: ["openid"],
            ip_prefix: "192.0.2.0/24",
            country: "CH",
            csrf: "device-csrf",
          },
        }
      : {
          status: 404,
          body: { type: "urn:suiss:access:problem:device-code-invalid", status: 404 },
        },
  );
  mock.json.set("POST /v1/device/approval", { status: 200, body: { decision: "approved" } });
}

// OP-154 m.3 (p), Ek B 4651
test("the device page shows the app, the scope and where the request came from", async ({
  page,
  mock,
}) => {
  device(mock);
  const csrf: string[] = [];
  await page.route("**/v1/device/approval", async (route) => {
    csrf.push(route.request().headers()["x-csrf-token"] ?? "");
    await route.fallback();
  });
  await page.goto("/device?user_code=BCDF-GHJZ");
  await expect(page.getByRole("heading", { name: "Connect a device" })).toBeVisible();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("request")).toHaveText(
    "Living room TV asks for openid. The request came from 192.0.2.0/24 in CH.",
  );
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByTestId("approved")).toHaveText(
    "The device is connected. You can close this page.",
  );
  expect(csrf).toEqual(["device-csrf"]);
});

// CR-39, Ek B 4650
test("a wrong code says only that it didn't work", async ({ page, mock }) => {
  device(mock);
  await page.goto("/device");
  await page.getByLabel("Code shown on the device").fill("ZZZZ-ZZZZ");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("invalid")).toHaveText(
    "This code didn't work. Check it and try again.",
  );
});
