// TN-134, OP-155 m.3 (i)
import { describe, expect, it } from "vitest";

import {
  isLink,
  linkOf,
  readSetup,
  setupPath,
  stepsFor,
  submitSetup,
  type Wizard,
} from "./index.js";

const LINK = "A".repeat(43);

describe("the SSO setup client", () => {
  it("names a link only by its 256-bit token", () => {
    expect(isLink(LINK)).toBe(true);
    expect(isLink("short")).toBe(false);
    expect(linkOf(`/realms/acme/login/sso-setup/${LINK}`)).toBe(LINK);
    expect(linkOf("/login/sso-setup/../x")).toBeNull();
    expect(setupPath("/realms/acme", LINK)).toBe(`/realms/acme/v1/sso-setup/${LINK}`);
  });

  it("keeps a wizard's steps of one protocol and the shared ones", () => {
    const w: Wizard = {
      v: 1,
      provider: "okta",
      name: "Okta",
      protocols: ["saml", "oidc"],
      scim: true,
      steps: [
        { action: "open", place: "Admin" },
        { protocol: "saml", action: "copy", value: "acs_url", field: "SSO URL" },
        { protocol: "oidc", action: "paste", input: "issuer", field: "Issuer" },
      ],
    };
    expect(stepsFor(w, "saml").map((s) => s.action)).toEqual(["open", "copy"]);
  });

  it("reads and submits on the realm's origin, a refusal by its problem code", async () => {
    const seen: { url: string; init: RequestInit | undefined }[] = [];
    const fetcher = ((url: string, init?: RequestInit) => {
      seen.push({ url, init });
      const status = init?.method === "POST" ? 410 : 200;
      const body =
        status === 200
          ? { organization: { id: "x", display_name: "Contoso" } }
          : { type: "urn:suiss:access:problem:setup-link-spent", status };
      return Promise.resolve(
        new Response(JSON.stringify(body), {
          status,
          headers: { "content-type": "application/json" },
        }),
      );
    }) as typeof fetch;
    const read = await readSetup("", LINK, fetcher);
    expect(read.ok && read.body.organization.display_name).toBe("Contoso");
    const spent = await submitSetup("", LINK, { step: "finish" }, fetcher);
    expect(spent).toEqual({ ok: false, status: 410, code: "setup-link-spent" });
    expect(seen[1]?.init?.credentials).toBe("same-origin");
    expect(new Headers(seen[1]?.init?.headers).get("idempotency-key")).toMatch(/.+/);
  });
});
