// OP-157 m.3 (l), §6.4, XI-4, Ek B 5596
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { approval } from "../index.js";

const intent: approval.DescribedIntent = {
  digest: "AAAA",
  action: { namespace: "access", name: "grant_issue", major: 1 },
  resources: [{ namespace: "pay.account", path: ["acc_1182"], incarnation: "0" }],
  params: { amount: "48500 eur", note: "Pay everyone" },
  opaque: [],
  recipient: null,
  validity: { from: 1, until: 2 },
};

describe("approval preview", () => {
  // XI-4, §6.4
  it("shows every typed parameter of the exact intent", () => {
    const types = { amount: "amount", note: "text" };
    expect(approval.complete(intent, types)).toBe(true);
    const html = renderToStaticMarkup(<approval.Preview intent={intent} types={types} />);
    expect(html).toContain("What you are about to sign");
    expect(html).toContain("access/grant_issue@1");
    expect(html).toContain("pay.account/acc_1182");
    expect(html).toContain("48500 eur");
    expect(html).toContain("Pay everyone");
    expect(html).toContain('data-type="amount"');
  });

  // OP-157 m.3 (l)
  it("never shows an untyped field and is then not complete", () => {
    const types = { amount: "amount" };
    expect(approval.untyped(intent, types)).toEqual(["note"]);
    expect(approval.complete(intent, types)).toBe(false);
    const html = renderToStaticMarkup(<approval.Preview intent={intent} types={types} />);
    expect(html).not.toContain("Pay everyone");
    expect(html).toContain(
      "This field has no declared type, so it can&#x27;t be shown in a preview.",
    );
    expect(html.toLowerCase()).not.toContain("independent");
  });
});
