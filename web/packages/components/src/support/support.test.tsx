import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  type Banner,
  type Request,
  SupportActions,
  SupportBanner,
  SupportRequest,
  SupportView,
} from "./index.js";

const request: Request = {
  organization: "Acme Support",
  case: "4411",
  what: "view your account settings",
  minutes: 60,
  readOnly: true,
};

const banner: Banner = { person: "Ayşe K.", case: "4411", readOnly: true, ends: "15:30" };

const none = () => undefined;

describe("support access", () => {
  // §8.16, OP-157 m.3 (f)
  it("gives access with the exact terms and never says approve", () => {
    const html = renderToStaticMarkup(
      <SupportRequest request={request} openedBy="user" onGive={none} onDecline={none} />,
    );
    expect(html).toContain("Give Acme Support access");
    expect(html).toContain(
      "view your account settings · case 4411 · for 60 minutes · can&#x27;t change sign-in methods, payments or email · can&#x27;t pass on",
    );
    expect(html).toContain("Give access");
    expect(html).toContain("Don&#x27;t give access");
    expect(html.toLowerCase()).not.toContain("approve");
  });

  // XI-7, OP-157 m.3 (f)
  it("is never opened by the operator who asked", () => {
    const html = renderToStaticMarkup(
      <SupportRequest request={request} openedBy="requester" onGive={none} onDecline={none} />,
    );
    expect(html).toBe("");
  });

  // X37, §8.16
  it("shows no support view without its banner", () => {
    expect(renderToStaticMarkup(<SupportView banner={undefined}>account</SupportView>)).toBe("");
    expect(
      renderToStaticMarkup(<SupportView banner={{ ...banner, case: "" }}>account</SupportView>),
    ).toBe("");
    const html = renderToStaticMarkup(<SupportView banner={banner}>account</SupportView>);
    expect(html).toContain(
      "Acting for Ayşe K. with their support access (case 4411) · read-only · ends 15:30 · every action is recorded under your name",
    );
    expect(html).toContain("account");
    expect(html.toLowerCase()).not.toContain("logged in as");
  });

  // §8.16
  it("names writable support access as such", () => {
    const html = renderToStaticMarkup(<SupportBanner banner={{ ...banner, readOnly: false }} />);
    expect(html).toContain("can change settings");
  });

  // §8.10, MD-9
  it("offers support access and break-glass in place of impersonation", () => {
    const html = renderToStaticMarkup(<SupportActions onRequest={none} onEmergency={none} />);
    expect(html).toContain("Request support access");
    expect(html).toContain("Emergency access (break-glass)");
    expect(html.toLowerCase()).not.toContain(["log", "in", "as"].join(" "));
    expect(renderToStaticMarkup(<SupportActions onRequest={none} />)).not.toContain("break-glass");
  });
});
