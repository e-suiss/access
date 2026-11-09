import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import {
  AgentBadge,
  AgentConnections,
  DelegationSuggestion,
  OutcomeLabels,
  StopRows,
} from "./Agents.js";
import {
  aftermath,
  connectionsOf,
  exposedOf,
  faceOf,
  limitLine,
  nextCheck,
  outcomeLines,
  passedOn,
  reportsOf,
  runtimeOf,
  runtimeOfJob,
  stopRows,
  suggestions,
} from "./model.js";

function some<T>(v: T | undefined): T {
  if (v === undefined) throw new Error("missing");
  return v;
}

const name = (p: string) => ({ ag: "Mail helper", al: "Alice", op: "Acme" })[p] ?? p;
const time = (ms: number) => `t${String(ms)}`;

describe("agent badge", () => {
  // XI-17, A-12, §8.17.5.11
  it("shows an agent as an agent with whom it acts for and its operator", () => {
    const face = faceOf({ party_kind: "agent", operator: "op" }, "ag", "al");
    expect(face).toEqual({ party: "ag", operator: "op", actingFor: "al" });
    const html = renderToStaticMarkup(<AgentBadge face={some(face)} name={name} />);
    expect(html).toContain("Agent · Acting for Alice · operated by Acme");
    expect(html).toContain('data-party-kind="agent"');
    expect(html).not.toMatch(/human|person/i);
  });

  // XI-17
  it("says the operator is not confirmed when no accepted Claim names one", () => {
    const html = renderToStaticMarkup(
      <AgentBadge face={some(faceOf({ party_kind: "agent" }, "ag"))} name={name} />,
    );
    expect(html).toContain("Agent · operator not confirmed");
  });

  // XI-17
  it("gives no face to anything that is not marked an agent", () => {
    expect(faceOf(undefined, "al")).toBeUndefined();
    expect(faceOf({ party_kind: "human" }, "al")).toBeUndefined();
  });
});

const use = {
  reports: {
    attested: [
      {
        reporter: "op",
        outcome: "done",
        evidence: ["upstream-confirmation"],
        at: 5,
        intent: "same",
      },
      { reporter: "op", outcome: "not-done", evidence: [], at: 6, intent: "same" },
      { reporter: "op", outcome: "unknown", evidence: [], at: 7, intent: "same" },
      { reporter: "op", outcome: "done", evidence: [], at: 8, intent: "different" },
      { reporter: "op", outcome: "said-so", evidence: [], at: 9, intent: "same" },
    ],
    control: [{ reporter: "op", state: "stopped_confirmed" }],
  },
};

describe("outcome labels", () => {
  // E64, INV-18, §8.17.10.3, X30
  it("labels each report with its reporter and evidence, and only what a runtime reported", () => {
    const lines = outcomeLines(reportsOf(use));
    expect(lines.map((l) => l.text)).toEqual([
      "outcome.attested_conforming",
      "outcome.not_done",
      "outcome.unknown",
      "outcome.attested_nonconforming",
    ]);
    const html = renderToStaticMarkup(<OutcomeLabels lines={lines} name={name} />);
    expect(html).toContain("Done as approved, reported by Acme");
    expect(html).toContain("confirmed by the service it acted on");
    expect(html).toContain("Done differently from what was approved");
    expect(html).not.toContain("said-so");
  });

  // E64
  it("says no report yet when no runtime reported", () => {
    expect(outcomeLines(reportsOf({})).map((l) => l.text)).toEqual(["outcome.unattested"]);
  });
});

describe("runtime state", () => {
  // §8.17.7.4, U5, §13.8
  it("is only what the runtime confirmed, else unknown", () => {
    expect(runtimeOf(reportsOf(use))).toBe("stopped");
    expect(
      runtimeOf(reportsOf({ reports: { control: [{ reporter: "op", state: "on_hold" }] } })),
    ).toBe("on_hold_confirmed");
    expect(runtimeOf(reportsOf({}))).toBe("unknown");
    expect(runtimeOfJob({ state: "running" })).toBe("running");
    expect(runtimeOfJob({ state: "stopped", confirmed: false })).toBe("unknown");
    expect(runtimeOfJob({ state: "stopped", confirmed: true })).toBe("stopped");
    expect(runtimeOfJob({ state: "held", confirmed: false })).toBe("unknown");
    expect(runtimeOfJob({ state: "completed" })).toBe("unknown");
  });
});

describe("Stop", () => {
  // §8.17.7.5, X13
  it("is two rows with their owners, never one Stopped", () => {
    const rows = stopRows("unknown", { text: "stop.authority_revoked", args: { time: "14:03" } });
    const html = renderToStaticMarkup(<StopRows rows={rows} />);
    expect(html.match(/<li/g)).toHaveLength(2);
    expect(html).toContain("Runtime");
    expect(html).toContain("We can&#x27;t tell right now whether it is running.");
    expect(html).toContain("Access");
    expect(html).toContain("Authority revoked 14:03");
    expect(html).not.toMatch(/>Stopped</);
  });
});

describe("aftermath", () => {
  const exposed = exposedOf({
    exposed: [{ exercise: "ex", holder: "ag", horizon_ms: 1_000, window_ms: 0 }],
  });

  // §8.13, §8.17.7.4, §8.17.5.8, E31
  it("is honest before and after the horizon and offers containment only when it went on", () => {
    const quiet = reportsOf({});
    expect(nextCheck(exposed, 500)).toBe(1_000);
    expect(nextCheck(exposed, 1_500)).toBeUndefined();
    expect(aftermath(some(exposed[0]), quiet, 500, time)).toEqual({
      runtime: "unknown",
      next: { text: "aftermath.within_window", args: { time: "t1000" } },
      containment: false,
    });
    expect(aftermath(some(exposed[0]), quiet, 1_500, time).next.text).toBe(
      "aftermath.after_window",
    );
    const late = reportsOf({
      reports: {
        attested: [{ reporter: "op", outcome: "done", evidence: [], at: 1_200, intent: "same" }],
      },
    });
    const after = aftermath(some(exposed[0]), late, 1_500, time);
    expect(after.next.text).toBe("aftermath.ignoring");
    expect(after.containment).toBe(true);
    expect(aftermath(some(exposed[0]), late, 900, time).containment).toBe(false);
  });
});

describe("sub-delegation", () => {
  // §8.17.7.1, X31
  it("lists what the holder passed on with its limits", () => {
    const passed = passedOn("g1", [
      {
        grant: "g2",
        source: { grant: "g1", holder: "ag" },
        who: { party: "sub" },
        limits: [{ dimension: { amount: "TRY" }, capacity: 1000, window: "total" }],
      },
      { grant: "g3", source: { anchor: "a" }, who: { party: "x" }, limits: [] },
    ]);
    expect(passed).toEqual([
      {
        grant: "g2",
        holder: "sub",
        limits: [{ text: "limit.amount", args: { capacity: "1000", unit: "TRY" } }],
      },
    ]);
    expect(limitLine({ dimension: "count", capacity: 3 })).toEqual({
      text: "limit.count",
      args: { capacity: "3" },
    });
  });
});

describe("delegation suggestion", () => {
  const day = 86_400_000;
  const approvals = Array.from({ length: 6 }, (_, i) => ({
    agent: "ag",
    action: "shop.refund",
    atMs: 10 * day - i * day,
    amount: { value: 100 + i * 20, unit: "TRY" },
  }));

  // §8.17.11.1, X8, XI-19
  it("suggests only after repeated approvals in a week, at most what was approved", () => {
    const s = suggestions(approvals, 10 * day);
    expect(s).toEqual([
      { agent: "ag", action: "shop.refund", count: 6, limit: { value: 200, unit: "TRY" } },
    ]);
    expect(suggestions(approvals.slice(0, 4), 10 * day)).toEqual([]);
    expect(suggestions(approvals, 30 * day)).toEqual([]);
  });

  // XI-19
  it("only opens the exact preview; it gives nothing by itself", () => {
    const html = renderToStaticMarkup(
      <DelegationSuggestion
        suggestion={some(suggestions(approvals, 10 * day)[0])}
        name={name}
        onReview={() => undefined}
        onDismiss={() => undefined}
      />,
    );
    expect(html).toContain("You approved 6 similar shop.refund requests from Mail helper");
    expect(html).toContain("Nothing changes until you review and give the exact delegation.");
    expect(html).toContain("Review the exact delegation");
    expect(html).not.toContain("Give access");
  });
});

describe("agent connections", () => {
  // §12.4.1, TN-133
  it("shows which agent used which account and offers one-click Disconnect, never a token", () => {
    const list = connectionsOf({
      connections: [
        {
          connection: "c1",
          upstream: "Gmail",
          status: "active",
          scopes: ["mail.read"],
          access_token: "secret",
          used: [
            { agent: "ag", exercise: "e1", released_ms: 5 },
            { agent: "ag", exercise: "e2", released_ms: 9 },
            { agent: null, exercise: "e3" },
          ],
        },
        { connection: "c2", upstream: "Slack", status: "needs_reconnect", scopes: [], used: [] },
        { connection: "c3", upstream: "Old", status: "disconnected", scopes: [], used: [] },
      ],
    });
    expect(list[0]?.used).toEqual([{ agent: "ag", atMs: 9 }]);
    const html = renderToStaticMarkup(
      <AgentConnections
        connections={list}
        name={name}
        time={time}
        onDisconnect={() => undefined}
      />,
    );
    expect(html).toContain("Gmail");
    expect(html).toContain("Used by Mail helper, last on t9");
    expect(html).toContain("Needs reconnecting");
    expect(html).toContain("No agent has used it yet");
    expect(html.match(/Disconnect</g)).toHaveLength(2);
    expect(html).not.toContain("secret");
  });
});
