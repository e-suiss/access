// OP-155 m.3 (l), IDP-14, §9.14.5 k.2, §10.5.3: the CIBA approval page names the client and its
// binding message, which binds nothing; declining answers the request with the page's CSRF token,
// and a request that expired or is not the person's says so without detail.
import { expect, test } from "./fixtures.js";

const REQUEST = "AZJw2b4kcuy1h2l1x3b0fA";

function ciba(mock: import("./mock.js").LoginMock, status = 200) {
  mock.json.set("POST /v1/ciba/preview", (body) =>
    (body as { request?: string }).request === REQUEST && status === 200
      ? {
          status: 200,
          body: {
            client: "Mail agent",
            binding_message: "Code 4F2Q",
            scopes: ["openid"],
            expires_at: Date.now() + 300_000,
            request: { require_action: {} },
            redirect_uri: "https://agent.example/cb",
            contribution_basis: null,
            domain: "AA",
            contribution: { class: "approve", envelope: "AA", valid_from: 1, valid_until: 2 },
            csrf: "ciba-csrf",
          },
        }
      : {
          status,
          body: { type: "urn:suiss:access:problem:ciba-request-expired", status },
        },
  );
  mock.json.set("POST /v1/ciba/approval", { status: 200, body: { decision: "denied" } });
}

// OP-155 m.3 (l), Ek B 4718
test("the CIBA page shows the client and its binding message, and declining needs the CSRF token", async ({
  page,
  mock,
}) => {
  ciba(mock);
  const sent: { csrf: string; body: unknown }[] = [];
  await page.route("**/v1/ciba/approval", async (route) => {
    sent.push({
      csrf: route.request().headers()["x-csrf-token"] ?? "",
      body: route.request().postDataJSON() as unknown,
    });
    await route.fallback();
  });
  await page.goto(`/login?reason=ciba&request=${REQUEST}`);
  await expect(
    page.getByRole("heading", { name: "Mail agent asks you to approve a request" }),
  ).toBeVisible();
  await expect(page.getByTestId("binding-message")).toHaveText(
    "Approve only if Mail agent shows this code: Code 4F2Q",
  );
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Don't approve", exact: true }).click();
  await expect(page.getByTestId("denied")).toHaveText("Not approved. Nothing was done.");
  expect(sent).toEqual([{ csrf: "ciba-csrf", body: { request: REQUEST, approve: false } }]);
});

// OP-155 m.3 (l)
test("an expired request says so", async ({ page, mock }) => {
  ciba(mock, 410);
  await page.goto(`/login?reason=ciba&request=${REQUEST}`);
  await expect(page.getByTestId("expired")).toHaveText("This request has expired.");
});

// §10.4.1, OP-155 m.3 (l), Ek B 4884
test("the device page shows no country when none is known", async ({ page, mock }) => {
  mock.json.set("POST /v1/device/preview", {
    status: 200,
    body: {
      client: "Living room TV",
      scopes: ["openid"],
      ip_prefix: "192.0.2.0/24",
      country: null,
      csrf: "device-csrf",
    },
  });
  await page.goto("/device?user_code=BCDF-GHJZ");
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByTestId("request")).toHaveText(
    "Living room TV asks for openid. The request came from 192.0.2.0/24.",
  );
});
