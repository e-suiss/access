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
            scopes: ["openid", "offline_access", "custom:thing"],
            ip_prefix: "192.0.2.0/24",
            country: "CH",
            account: "ada@example.org",
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
  await page.goto("/device?user_code=bcdf-ghjz");
  await expect(page.getByRole("heading", { name: "Connect a device" })).toBeVisible();
  await expect(page.getByLabel("Code shown on the device")).toHaveAttribute("autocomplete", "off");
  await page.getByRole("button", { name: "Continue" }).click();
  // TN-160
  await expect(page.getByTestId("match")).toHaveText(
    "Your device should show this code: BCDF-GHJZ",
  );
  await expect(page.getByTestId("request")).toHaveText("Living room TV asks to:");
  await expect(page.getByTestId("scopes").locator("li")).toHaveText([
    "Sign you in with your account",
    "Keep access while you're not using it",
    "custom:thing",
  ]);
  await expect(page.getByTestId("origin")).toHaveText(
    "The request came from Switzerland (network 192.0.2.0/24).",
  );
  await expect(page.getByTestId("warning")).toContainText("If someone else sent you this code");
  await expect(page.getByTestId("account")).toContainText("You're approving as ada@example.org.");
  await expect(page.getByRole("link", { name: "Use another account" })).toHaveAttribute(
    "href",
    /return_to=.*%2Fdevice%3Fuser_code%3DBCDF-GHJZ/,
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

// TN-160: a person who isn't signed in signs in and comes back with the code
test("a person who isn't signed in signs in and comes back to the code", async ({ page, mock }) => {
  mock.json.set("POST /v1/device/preview", {
    status: 401,
    body: { type: "urn:suiss:access:problem:session-required", status: 401 },
  });
  await page.route("**/login?return_to=*", (r) =>
    r.fulfill({ status: 200, contentType: "text/html", body: "<title>login</title>" }),
  );
  await page.goto("/device?user_code=BCDF-GHJZ");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/login\?return_to=.*%2Fdevice%3Fuser_code%3DBCDF-GHJZ/);
});
