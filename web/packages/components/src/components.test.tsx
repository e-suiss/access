import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { StatusLadder, StepUp, WhyPanel, honesty } from "./index.js";
import type { Explanation, Rung } from "./index.js";

const rungs: Rung[] = [
  { text: "ladder.requested", owner: "requester", state: "reached" },
  { text: "ladder.approval_recorded", owner: "access", state: "not_applicable" },
  { text: "ladder.gate_satisfied", owner: "coordinator", state: "not_applicable" },
  { text: "ladder.allowed", owner: "access", state: "reached" },
  { text: "ladder.started", owner: "executor", state: "unknown" },
  { text: "ladder.reported_unknown", owner: "executor", state: "unknown" },
];

describe("StatusLadder", () => {
  // XI-2, X39
  it("shows every rung with its owner and its state in words", () => {
    const html = renderToStaticMarkup(<StatusLadder rungs={rungs} />);
    expect(html.match(/<li/g)).toHaveLength(6);
    expect(html).toContain("Allowed");
    expect(html).toContain("Runtime");
    expect(html).toContain("Unknown — not reported");
    expect(html).toContain("not reported");
    expect(html).not.toContain("Stopped");
  });
});

const why: Explanation = {
  source: "decision_record",
  when: "past",
  summary: "Your limit is 2,000 TRY a day.",
  owners: [
    { owner: "Access", line: "Delegation limit 2,000 TRY/day" },
    { owner: "Pay", line: "Card limit 5,000 TRY/day" },
  ],
  couldChange: ["Ask the person who gave it to raise the limit"],
  expert: ["Grant from Alice, revision 2"],
};

describe("WhyPanel", () => {
  // XI-9, §8.5, X18
  it("labels where the answer comes from and keeps owners apart", () => {
    const html = renderToStaticMarkup(<WhyPanel explanation={why} depth="default" />);
    expect(html).toContain("From the decision record");
    expect(html).toContain("As decided at that time");
    expect(html.match(/access-owner-badge/g)).toHaveLength(2);
    expect(html).not.toContain("revision 2");
    const advisory = renderToStaticMarkup(
      <WhyPanel
        explanation={{ ...why, source: "advisory", when: "hypothetical" }}
        depth="default"
      />,
    );
    expect(advisory).toContain("Advisory — not recorded");
    expect(advisory).toContain("If asked now");
  });

  // §8.12, X25
  it("offers only the depths the viewer may see", () => {
    const html = renderToStaticMarkup(<WhyPanel explanation={why} depth="expert" />);
    expect(html).toContain("revision 2");
    expect(html).toContain("Details");
    expect(html).not.toContain(">Audit<");
  });
});

describe("StepUp", () => {
  // XI-19
  it("has no remember-this option", () => {
    const html = renderToStaticMarkup(
      <StepUp
        reason="This payment is over your limit."
        method="Use your security key."
        onStart={() => undefined}
        onCancel={() => undefined}
      />,
    );
    expect(html.toLowerCase()).not.toMatch(/remember|don.t ask|skip/);
    expect(html).toContain("Confirm it&#x27;s you");
  });
});

describe("honesty", () => {
  const base: honesty.Attempt = {
    sent: "sent",
    path: "direct",
    answer: { kind: "nothing" },
    timedOut: false,
    validUntil: 1_000,
  };

  // XI-3
  it("shows submitted until the answer is recorded", () => {
    expect(honesty.shown(base)).toBe("outcome.submitted");
    expect(
      honesty.shown({
        ...base,
        answer: honesty.answerOf(200, { decision: true, context: { exercise: "e" } }),
      }),
    ).toBe("outcome.confirmed");
  });

  // G39, X26, HL-5, TI-8
  it("never shows an unknown outcome as done or not recorded", () => {
    const lost = { ...base, timedOut: true };
    expect(honesty.shown(lost)).toBe("outcome.not_confirmed_checking");
    expect(honesty.next(lost, 999)).toBe("retry_same_nonce");
    expect(honesty.next(lost, 1_000)).toBe("query_outcome");
    expect(honesty.shown({ ...lost, path: "mediated", sent: "never" })).toBe(
      "outcome.not_confirmed_checking",
    );
    expect(honesty.shown({ ...lost, sent: "never" })).toBe("outcome.couldnt_reach");
    expect(honesty.answerOf(503, { reason: "sequencer" })).toEqual({ kind: "nothing" });
    expect(honesty.answerOf(503, { reason: "time" })).toEqual({ kind: "no_time" });
  });
});
