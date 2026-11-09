// §11.6, AS-M14, AG-6, X-L8, OP-154 m.3 (k): the consent screen of a client the realm did not
// register shows the hostnames always and the client's name only as its own claim; it never says
// Allow; declining answers the app with access_denied.
import { expect, test } from "./fixtures.js";

const returnTo =
  "/authorize?client_id=https%3A%2F%2Fapp.example%2Fclient.json&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc";

function approval(mock: import("./mock.js").LoginMock, draft: unknown, loopback = false) {
  mock.json.set("POST /v1/login/approval/preview", {
    status: 200,
    body: {
      client_id: "https://app.example/client.json",
      client_host: "app.example",
      client_says: "Photo Prints",
      redirect_hosts: loopback ? ["127.0.0.1"] : ["app.example"],
      loopback_only: loopback,
      new_app: true,
      visual_changed: false,
      resource: "https://mcp.example.com/mcp",
      scopes: [],
      csrf: "csrf-token",
      draft,
    },
  });
  mock.json.set("POST /v1/login/approval/decline", {
    status: 200,
    body: { redirect_to: "/callback?error=access_denied" },
  });
}

// AS-M14, §11.3, OP-154 m.3 (i), Ek B 4246, 4247, 4249
test("the consent screen names the hostnames and the client's own claim, never Allow", async ({
  page,
  mock,
}) => {
  approval(mock, null);
  await page.goto(`/login?reason=approve&return_to=${encodeURIComponent(returnTo)}`);
  await expect(page.getByRole("heading", { name: "app.example asks for access" })).toBeVisible();
  await expect(page.getByTestId("client-says")).toHaveText(
    "The app calls itself Photo Prints. Access hasn't checked this name.",
  );
  await expect(page.getByTestId("redirect-host")).toHaveText([
    "After you answer, you go to app.example.",
  ]);
  await expect(page.getByTestId("new-app")).toBeVisible();
  await expect(page.getByTestId("loopback")).toHaveCount(0);
  const words = await page.locator("main").innerText();
  expect(words).not.toMatch(/\b(allow|authori[sz]e)\b/i);
  // EI-18: nothing to sign, nothing to approve
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
});

// AG-6, Ek B 4248
test("a client that only redirects to this device gets the extra warning", async ({
  page,
  mock,
}) => {
  approval(mock, null, true);
  await page.goto(`/login?reason=approve&return_to=${encodeURIComponent(returnTo)}`);
  await expect(page.getByTestId("loopback")).toHaveText(
    "This app sends you back to a program on this device. Approve only if you started it.",
  );
});

// X-L8, §11.4.5 #28
test("Don't approve answers the app and carries the CSRF token", async ({ page, mock }) => {
  approval(mock, null);
  const csrf: string[] = [];
  await page.route("**/v1/login/approval/decline", async (route) => {
    csrf.push(route.request().headers()["x-csrf-token"] ?? "");
    await route.fallback();
  });
  await page.goto(`/login?reason=approve&return_to=${encodeURIComponent(returnTo)}`);
  await page.getByRole("button", { name: "Don't approve" }).click();
  await expect(page.getByTestId("declined")).toHaveText("You chose not to continue.");
  await expect(page).toHaveURL(/error=access_denied/);
  expect(csrf).toEqual(["csrf-token"]);
});

test("a return address on another site is not followed", async ({ page, mock }) => {
  approval(mock, null);
  await page.goto(
    `/login?reason=approve&return_to=${encodeURIComponent("https://evil.example/x")}`,
  );
  await expect(page.getByRole("alert")).toHaveText(
    "Access couldn't complete this request. Try again shortly.",
  );
  expect(mock.posted).toEqual([]);
});
