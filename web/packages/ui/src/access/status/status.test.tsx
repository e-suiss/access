// OP-158 m.3 (e), (t), XI-20, CL-2, X14, Ek B 5740, 5744
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { honesty, status } from "../index.js";

describe("status", () => {
  it("shows owner, UNKNOWN, what is missing and the safe default of every failure", () => {
    const html = renderToStaticMarkup(
      <status.DegradedNotice
        state={{
          id: "FO-18",
          owner: "access",
          missing: "revocations made elsewhere",
          safeDefault: "no new sign-in; tokens end at their own expiry",
        }}
      />,
    );
    expect(html).toContain('data-failure="FO-18"');
    expect(html).toContain("Responsible: Access");
    expect(html).toContain("UNKNOWN");
    expect(html).toContain("Not known yet: revocations made elsewhere");
    expect(html).toContain("Until then: no new sign-in; tokens end at their own expiry");
  });

  it("keeps a revocation confirming until witnessed_through covers it", () => {
    const pending = (r: status.Recorded) =>
      renderToStaticMarkup(<status.RevocationStatus recorded={r} />);
    expect(pending({ pos: "12", ack: "pending", witnessedThrough: "12" })).toContain(
      "Revoked — confirming (witness pending)",
    );
    expect(pending({ pos: "12", witnessedThrough: "11" })).toContain("witness pending");
    expect(pending({ pos: "12", ack: "witnessed", witnessedThrough: "12" })).toContain(
      'data-state="witnessed"',
    );
    expect(status.witnessed({ pos: "x", ack: "witnessed" })).toBe(false);
    expect(status.witnessed({ pos: "12", ack: "witnessed" })).toBe(true);
    expect(status.witnessed({ pos: "12" })).toBe(false);
  });

  it("reads ack pending and a busy 503 from the ADP answer", () => {
    const base: honesty.Attempt = {
      sent: "sent",
      path: "direct",
      answer: honesty.answerOf(200, {
        decision: true,
        context: { exercise: "e", ack: "pending" },
      }),
      timedOut: false,
      validUntil: 1_000,
    };
    expect(honesty.shown(base)).toBe("outcome.witness_pending");
    expect(honesty.shown({ ...base, revocation: true })).toBe("outcome.revoked_confirming");
    expect(honesty.next({ ...base, revocation: true }, 0)).toBe("done");
    expect(honesty.answerOf(503, { reason: "busy" })).toEqual({ kind: "busy" });
    expect(honesty.answerOf(503, { reason: "time" })).toEqual({ kind: "no_time" });
  });
});
