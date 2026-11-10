// OP-156 m.3 (u), (v), XI-14, E21, F9, §8.11, §8.17.5.11, X30, E26, R8, X8
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { delegationPage, offline, payment } from "../index.js";

const period = (p: string) => ({ transaction: "order", day: "day", month: "month" })[p] ?? p;

describe("payment", () => {
  // XI-14
  it("shows the authority limit and the financial limit as two rows with two owners", () => {
    const rows = payment.limitRows(
      [{ dimension: { amount: "try" }, capacity: 50_000, window: "total" }],
      [
        {
          limit: { currency: "TRY", minor: 500_000 },
          period: "day",
          held: { currency: "TRY", minor: 12_000 },
        },
      ],
      "en",
      period,
    );
    expect(rows.map((r) => [r.owner, r.line.text])).toEqual([
      ["access", "limit.authority"],
      ["pay", "limit.financial"],
      ["pay", "limit.held"],
    ]);
    const html = renderToStaticMarkup(<payment.LimitRows rows={rows} />);
    expect(html).toContain("Authority limit (Access): TRY");
    expect(html).toContain("500.00");
    expect(html).toContain("Financial limit (Pay): TRY");
    expect(html).toContain("5,000.00 / day");
    expect(html).toContain("120.00 held by Pay");
    // XI-14: nothing is derived from the other owner's figure
    expect(payment.limitRows([], [], "en", period)).toEqual([]);
    expect(
      payment
        .limitRows(
          [{ dimension: { amount: "try" }, capacity: 50_000, window: "total" }],
          [],
          "en",
          period,
        )
        .every((r) => r.owner === "access"),
    ).toBe(true);
  });

  // §8.17.5.11, R8, X8, INV-20
  it("pays once with the exact amount and recipient, and refuses a request that is not one-time", () => {
    const html = renderToStaticMarkup(
      <payment.OneTimePayment
        payment={{
          amount: { currency: "TRY", minor: 30_000 },
          recipient: "TQ",
          purpose: "order-1182",
          until: 1,
        }}
        merchant="Kaya Tekstil"
        locale="en"
        onPay={() => undefined}
        onCancel={() => undefined}
      />,
    );
    expect(html).toContain("Pay TRY");
    expect(html).toContain("300.00 to Kaya Tekstil once. Nothing more can be charged with this.");
    expect(html).toContain("For order-1182");
    expect(html).toContain("Pay once");
    const refused = renderToStaticMarkup(
      <payment.OneTimePayment
        payment="authority_change"
        merchant="Kaya Tekstil"
        locale="en"
        onPay={() => undefined}
        onCancel={() => undefined}
      />,
    );
    expect(refused).toContain("would let Kaya Tekstil charge you again");
    expect(refused).not.toContain("Pay once");
  });

  // §8.17.5.11
  it("keeps saving a card a verb and a preview of its own", () => {
    const html = renderToStaticMarkup(
      <payment.SaveCard
        merchant="M"
        perOrder={{ currency: "TRY", minor: 50_000 }}
        until="31 Dec 2026"
        locale="en"
        onConfirm={() => undefined}
        onCancel={() => undefined}
      />,
    );
    expect(html).toContain("Let M charge your card: up to TRY");
    expect(html).toContain("per order, until 31 Dec 2026, only for orders you place");
    expect(html).not.toContain("once");
  });

  // §8.11, §8.17.7.2, X30, E26, X24
  it("lists merchants with the agent badge, Pay's objects as separate rows and no internal decisions", () => {
    const html = renderToStaticMarkup(
      <payment.Merchants
        merchants={[
          {
            grant: "g1",
            name: "M",
            agent: true,
            limits: payment.limitRows(
              [{ dimension: { amount: "eur" }, capacity: 50_000, window: "total" }],
              [],
              "en",
              period,
            ),
            pay: [
              {
                kind: "agreement",
                label: "SEPA mandate MR-221",
                href: "https://pay.example/a/221",
              },
              { kind: "consent", label: "Open banking consent C-9", href: "javascript:alert(1)" },
            ],
          },
        ]}
        onStop={() => undefined}
      />,
    );
    expect(html).toContain("AI agent · acting for M");
    expect(html).toContain('data-party-kind="agent"');
    expect(html).toContain("SEPA mandate MR-221 · based on your delegation to M (€500.00)");
    expect(html).toContain('href="https://pay.example/a/221"');
    expect(html).not.toContain("javascript:");
    expect(html).toContain("Open banking consent C-9 is managed in Pay");
    expect(html).toContain("two separate steps");
    expect(html).toContain("Stop charges");
    expect(html).toContain("What M decides inside its own business isn&#x27;t shown here.");
    expect(
      renderToStaticMarkup(<payment.Merchants merchants={[]} onStop={() => undefined} />),
    ).toContain("No merchant can charge you.");
  });
});

describe("offline", () => {
  const time = (ms: number) => `t${String(ms)}`;
  // §8.17.5.8, CI-9
  it("shows the till's window with its condition and, once ended, only that it must go online", () => {
    const report = {
      since: 1,
      until: 2,
      voidsLeft: 3,
      amountLeft: { currency: "TRY", minor: 200_000 },
    };
    const html = renderToStaticMarkup(
      <offline.OfflineStatus state={{ kind: "offline", report }} time={time} locale="en" />,
    );
    expect(html).toContain("Offline since t1");
    expect(html).toContain("Can act offline until t2, if it follows its declared offline profile");
    expect(html).toContain("3 voids and TRY");
    expect(html).toContain("2,000.00 left until this till must go online");
    const ended = renderToStaticMarkup(
      <offline.OfflineStatus state={{ kind: "ended", report }} time={time} locale="en" />,
    );
    expect(ended).toContain(
      "The offline period ended at t2. This till must go online to continue.",
    );
    expect(ended).not.toMatch(/allowed|can act/i);
    expect(
      renderToStaticMarkup(
        <offline.OfflineStatus state={{ kind: "online" }} time={time} locale="en" />,
      ),
    ).toBe("");
  });
});

describe("delegation page", () => {
  const row = {
    grant: "g1",
    owner: "access",
    status: "status.current",
    who: { kind: "group" },
    source: { text: "source.sync_from_hr", issuer: "hr" },
    capacity: [{ text: "capacity.as_yourself" }],
    what: ["work:approve"],
    validity: { valid_until: 9 },
    limits: [
      {
        kind: "authority" as const,
        owner: "access",
        term: { dimension: { amount: "try" }, capacity: 50_000, window: "total" },
      },
      {
        kind: "financial" as const,
        owner: "pay",
        term: { currency: "TRY", limit_minor: 500_000, period: "day" },
        as_of: 5,
      },
    ],
    offers: [{ action: "revoke", available: true }],
  };
  // §18.3, §18.8.1 H5, §8.13, XI-14, INV-24, IA-1
  it("renders the hub with its owners, both limits, the notices and the coordinator link", () => {
    const html = renderToStaticMarkup(
      <delegationPage.DelegationPage
        hub={{
          as_of: 1,
          your_authority: [row],
          acting_for_you: [],
          shared_from_you: [],
          notices: [
            "hub.not_shown_unconnected",
            "status.notifications_delayed",
            "status.access_unavailable",
          ],
          attention: { href: "https://work.example/attention", count: 2 },
        }}
        name={(p) => p}
        time={(ms) => `t${String(ms)}`}
        locale="en"
        onRevoke={() => undefined}
      />,
    );
    expect(html).toContain("Sync from HR (hr)");
    expect(html).toContain("Authority limit (Access)");
    expect(html).toContain("Financial limit (Pay)");
    expect(html).toContain("Notifications are delayed. What you changed still took effect.");
    expect(html).toContain(
      "Authority can&#x27;t be changed right now. You can still ask the runtime to stop for now (Work control)",
    );
    expect(html).not.toMatch(/pending|disabled|queued/i);
    expect(html).toContain("2 approvals waiting for you →");
    expect(html).toContain("Revoke");
  });
});
