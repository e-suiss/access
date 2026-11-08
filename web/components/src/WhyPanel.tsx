// S5, XI-9, X18, §8.5, §8.17.8.3, §8.17.8.4, X25
import { text } from "./texts.js";

export type Depth = "default" | "expert" | "audit";

export interface OwnerLine {
  /** Whose rule or record this line is: Access, Commerce, Work, Pay. */
  readonly owner: string;
  /** The line, already in the viewer's language. */
  readonly line: string;
}

export interface Explanation {
  /** Where the answer comes from: a recorded decision, or an advisory evaluation. */
  readonly source: "decision_record" | "advisory";
  /** As decided at that time, or what would happen if asked now. */
  readonly when: "past" | "hypothetical";
  /** The summary, already in the viewer's language. */
  readonly summary: string;
  /** One line per owner, never merged (§8.5 decision 3). */
  readonly owners: readonly OwnerLine[];
  /** Only the canonical actions that could change the answer, nearest first. */
  readonly couldChange: readonly string[];
  /** What the expert depth adds, if the viewer may see it. */
  readonly expert?: readonly string[];
  /** What the audit depth adds, only when the viewer holds audit authority. */
  readonly audit?: readonly string[];
}

export interface WhyPanelProps {
  readonly explanation: Explanation;
  readonly depth: Depth;
  readonly onDepth?: (d: Depth) => void;
  readonly catalogue?: Readonly<Record<string, string>>;
}

/** The "Why?" panel: the same component on every surface. Each depth explains the one before
 * and never contradicts it; a depth the viewer may not see is not offered. */
export function WhyPanel({ explanation: e, depth, onDepth, catalogue }: WhyPanelProps) {
  const depths: Depth[] = ["default"];
  if (e.expert) depths.push("expert");
  if (e.audit) depths.push("audit");
  return (
    <section className="access-why" aria-label={text("why.could_change", catalogue)}>
      <p className="access-why-source">
        {text(e.source === "decision_record" ? "why.derived" : "why.advisory", catalogue)}
        {" · "}
        {text(e.when === "past" ? "why.past" : "why.hypothetical", catalogue)}
      </p>
      <p className="access-why-summary">{e.summary}</p>
      <ul className="access-why-owners">
        {e.owners.map((o) => (
          <li key={`${o.owner}:${o.line}`}>
            <span className="access-owner-badge">{o.owner}</span> {o.line}
          </li>
        ))}
      </ul>
      {e.couldChange.length > 0 && (
        <>
          <h3>{text("why.could_change", catalogue)}</h3>
          <ol className="access-why-change">
            {e.couldChange.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ol>
        </>
      )}
      {depth !== "default" && e.expert && (
        <ul className="access-why-expert">
          {e.expert.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      )}
      {depth === "audit" && e.audit && (
        <ul className="access-why-audit">
          {e.audit.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      )}
      {depths.length > 1 && (
        <div role="group" className="access-why-depths">
          {depths.map((d) => (
            <button key={d} type="button" aria-pressed={d === depth} onClick={() => onDepth?.(d)}>
              {text(`why.depth.${d}`, catalogue)}
            </button>
          ))}
        </div>
      )}
    </section>
  );
}
