// OP-156 m.3 (t), §8.17.6.1, §8.17.6.5, §8.17.7.2, IA-1, X6, X7
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { work } from "../index.js";

describe("work", () => {
  // §8.17.7.2, IA-3
  it("says which commitment a holding ends with, under the Work badge", () => {
    const html = renderToStaticMarkup(
      <work.CommitmentLink commitment="C-77" href="https://work.example/c/77" />,
    );
    expect(html).toContain("Work");
    expect(html).toContain('href="https://work.example/c/77"');
    expect(html).toContain("Ends with Work commitment C-77");
    const unsafe = renderToStaticMarkup(
      <work.CommitmentLink commitment="C-77" href="javascript:alert(1)" />,
    );
    expect(unsafe).not.toContain("href");
  });

  // IA-1, X6
  it("links to the coordinator's queue with its count and shows nothing otherwise", () => {
    const html = renderToStaticMarkup(
      <work.AttentionLink attention={{ href: "https://work.example/attention", count: 3 }} />,
    );
    expect(html).toContain("3 approvals waiting for you →");
    expect(renderToStaticMarkup(<work.AttentionLink />)).toBe("");
    expect(
      renderToStaticMarkup(
        <work.AttentionLink attention={{ href: "https://work.example/a", count: 0 }} />,
      ),
    ).toBe("");
    expect(
      renderToStaticMarkup(
        <work.AttentionLink attention={{ href: "http://work.example/a", count: 2 }} />,
      ),
    ).toBe("");
  });

  // §8.17.6.1, X7
  it("writes a partial failure honestly and never as proceeding", () => {
    const html = renderToStaticMarkup(<work.GateStatus recorded gateUpdated={false} />);
    expect(html).toContain("Approval recorded (Access); gate not updated yet (Work)");
    expect(html).not.toMatch(/proceeding|allowed/i);
    expect(renderToStaticMarkup(<work.GateStatus recorded gateUpdated />)).toBe("");
    expect(renderToStaticMarkup(<work.GateStatus recorded={false} gateUpdated={false} />)).toBe("");
  });
});
