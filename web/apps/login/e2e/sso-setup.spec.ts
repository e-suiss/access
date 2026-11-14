// TN-133, TN-134, OP-155 m.3 (i): the hosted SSO setup portal is <OrganizationSSO /> over the
// realm's setup API. Reading spends nothing, a step drafts the connection the wizard filled in,
// the test waits for an owner, and a spent or expired link says so without detail.
import AxeBuilder from "@axe-core/playwright";

import { expect, test } from "./fixtures.js";
import type { LoginMock } from "./mock.js";

const LINK = "s".repeat(43);
const wcag22aa = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

function setup(mock: LoginMock, status = 200): void {
  mock.json.set(`GET /v1/sso-setup/${LINK}`, {
    status,
    body:
      status === 200
        ? {
            organization: { id: "Wlpa", display_name: "Contoso" },
            expires_at: "2026-11-13T09:00:00Z",
            opened: false,
            connection: "org-5a5a5a5a5a5a",
            values: {
              entity_id: "https://acme.localhost/v1/login/upstream/org-5a5a5a5a5a5a/saml/metadata",
              acs_url: "https://acme.localhost/v1/login/upstream/org-5a5a5a5a5a5a/saml/acs",
              metadata_url:
                "https://acme.localhost/v1/login/upstream/org-5a5a5a5a5a5a/saml/metadata",
              redirect_uri: "https://acme.localhost/v1/login/upstream/org-5a5a5a5a5a5a/callback",
              scim_base_url: "https://acme.localhost/scim/v2",
            },
            wizards: [
              {
                v: 1,
                provider: "okta",
                name: "Okta",
                protocols: ["saml"],
                scim: true,
                steps: [
                  { action: "open", place: "Applications > Create App Integration" },
                  { action: "copy", value: "acs_url", field: "Single sign-on URL" },
                  { action: "paste", input: "entity_id", field: "Issuer" },
                  { action: "paste", input: "metadata_url", field: "Metadata URL" },
                ],
              },
            ],
            domains: [
              {
                domain: "contoso.example",
                method: "dns_txt",
                verified: false,
                txt_name: "_suiss-access.contoso.example",
              },
            ],
            scim: { bound: false },
            drafts: [],
            test: "after_enactment",
            texts: {},
          }
        : { type: "urn:suiss:access:problem:setup-link-spent", status },
  });
  mock.json.set(`POST /v1/sso-setup/${LINK}`, (body) =>
    (body as { step?: string }).step === "finish"
      ? { status: 200, body: { finished: true } }
      : { status: 201, body: { drafted: true, text: "sso_setup.test" } },
  );
}

// TN-134, OP-155 m.3 (i), Ek B 4874, 4880, 4914, 4933
test("the portal drafts the connection the wizard filled in and keeps the test for an owner", async ({
  page,
  mock,
}) => {
  setup(mock);
  await page.goto(`/login/sso-setup/${LINK}`);
  await expect(page.getByRole("heading", { name: "Set up sign-in for Contoso" })).toBeVisible();
  await expect(page.getByLabel("Single sign-on URL")).toHaveValue(
    "https://acme.localhost/v1/login/upstream/org-5a5a5a5a5a5a/saml/acs",
  );
  await expect(page.getByText("_suiss-access.contoso.example")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Sign in once to test the connection." }),
  ).toBeDisabled();
  expect((await new AxeBuilder({ page }).withTags(wcag22aa).analyze()).violations).toEqual([]);
  await page.getByLabel("Issuer").fill("http://www.okta.com/exk1");
  await page.getByLabel("Metadata URL").fill("https://contoso.okta.com/app/exk1/sso/saml/metadata");
  await page.getByRole("button", { name: "Save the connection" }).click();
  await expect(page.getByTestId("note")).toHaveText("Sign in once to test the connection.");
  const posted = mock.posted.filter((p) => p.key === `POST /v1/sso-setup/${LINK}`);
  expect(posted[0]?.body).toEqual({
    step: "connection",
    provider: "okta",
    protocol: "saml",
    entity_id: "http://www.okta.com/exk1",
    metadata_url: "https://contoso.okta.com/app/exk1/sso/saml/metadata",
  });
  await page.getByRole("button", { name: "Finish setup" }).click();
  await expect(page.getByTestId("finished")).toHaveText(
    "The connection works. An owner of Contoso can now turn it on.",
  );
});

// TN-134
test("a spent or expired link says so", async ({ page, mock }) => {
  setup(mock, 410);
  await page.goto(`/login/sso-setup/${LINK}`);
  await expect(page.getByTestId("expired")).toHaveText(
    "This setup link has expired or was already used. Ask for a new one.",
  );
});
