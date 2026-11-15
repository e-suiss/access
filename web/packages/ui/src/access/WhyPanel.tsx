// S5, XI-9, X18, §8.5, §8.17.8.3, §8.17.8.4, X25
import { Badge } from "@access/ui/components/badge";
import { Button } from "@access/ui/components/button";
import { Card, CardContent, CardFooter } from "@access/ui/components/card";

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
    <Card
      size="sm"
      variant="filled"
      role="region"
      className="access-why"
      aria-label={text("why.could_change", catalogue)}
    >
      <CardContent className="flex flex-col gap-3">
        <p className="access-why-source text-sm text-muted-foreground">
          {text(e.source === "decision_record" ? "why.derived" : "why.advisory", catalogue)}
          {" · "}
          {text(e.when === "past" ? "why.past" : "why.hypothetical", catalogue)}
        </p>
        <p className="access-why-summary text-base">{e.summary}</p>
        <ul className="access-why-owners flex flex-col gap-2">
          {e.owners.map((o) => (
            <li key={`${o.owner}:${o.line}`} className="flex flex-wrap items-center gap-2 text-sm">
              <Badge variant="outline" className="access-owner-badge">
                {o.owner}
              </Badge>{" "}
              {o.line}
            </li>
          ))}
        </ul>
        {e.couldChange.length > 0 && (
          <>
            <h3 className="text-sm font-semibold">{text("why.could_change", catalogue)}</h3>
            <ol className="access-why-change list-decimal ps-5 text-sm">
              {e.couldChange.map((c) => (
                <li key={c}>{c}</li>
              ))}
            </ol>
          </>
        )}
        {depth !== "default" && e.expert && (
          <ul className="access-why-expert list-disc ps-5 text-sm text-muted-foreground">
            {e.expert.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        )}
        {depth === "audit" && e.audit && (
          <ul className="access-why-audit list-disc ps-5 font-mono text-xs text-muted-foreground">
            {e.audit.map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
        )}
      </CardContent>
      {depths.length > 1 && (
        <CardFooter role="group" className="access-why-depths gap-2">
          {depths.map((d) => (
            <Button
              key={d}
              type="button"
              size="sm"
              variant={d === depth ? "secondary" : "ghost"}
              aria-pressed={d === depth}
              onClick={() => onDepth?.(d)}
            >
              {text(`why.depth.${d}`, catalogue)}
            </Button>
          ))}
        </CardFooter>
      )}
    </Card>
  );
}
