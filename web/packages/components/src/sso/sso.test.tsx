// TN-133, TN-134, OP-155 m.3 (i)
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { sso } from "../index.js";

const setup: sso.OrganizationSetup = {
  organization: { id: "Wlpa", display_name: "<Contoso>" },
  values: {
    entity_id: "https://id.example/v1/login/upstream/org-1/saml/metadata",
    acs_url: "https://id.example/v1/login/upstream/org-1/saml/acs",
    scim_base_url: "https://id.example/scim/v2",
  },
  wizards: [
    {
      provider: "okta",
      name: "Okta",
      protocols: ["saml", "oidc"],
      scim: true,
      steps: [
        { action: "open", place: "Applications > Create App Integration" },
        { protocol: "saml", action: "copy", value: "acs_url", field: "Single sign-on URL" },
        { protocol: "saml", action: "paste", input: "metadata_url", field: "Metadata URL" },
        { protocol: "oidc", action: "paste", input: "issuer", field: "Issuer" },
      ],
    },
  ],
  domains: [
    { domain: "contoso.example", verified: false, txt_name: "_suiss-access.contoso.example" },
  ],
  drafts: [],
  test: "after_enactment",
};

describe("OrganizationSSO", () => {
  // TN-134
  it("draws the wizard's steps of one protocol, the values to copy and the domains", () => {
    const html = renderToStaticMarkup(
      <sso.OrganizationSSO setup={setup} onSubmit={() => undefined} />,
    );
    expect(html).toContain("Set up sign-in for &lt;Contoso&gt;");
    expect(html).toContain("Single sign-on URL");
    expect(html).toContain(setup.values["acs_url"]);
    expect(html).toContain("Metadata URL");
    expect(html).not.toContain(">Issuer<");
    expect(html).toContain("_suiss-access.contoso.example");
    expect(html).toContain("https://id.example/scim/v2");
  });

  // TN-95
  it("keeps the test off until an owner enacts the connection", () => {
    const html = renderToStaticMarkup(
      <sso.OrganizationSSO setup={setup} onSubmit={() => undefined} />,
    );
    expect(html).toMatch(
      /<button type="button" disabled="">Sign in once to test the connection.<\/button>/,
    );
    const ready = renderToStaticMarkup(
      <sso.OrganizationSSO setup={{ ...setup, test: "ready" }} onSubmit={() => undefined} />,
    );
    expect(ready).not.toMatch(/disabled=""/);
  });

  it("keeps a wizard's shared steps with each protocol", () => {
    const w = setup.wizards[0];
    expect(w && sso.stepsOf(w, "oidc").map((s) => s.action)).toEqual(["open", "paste"]);
  });
});
