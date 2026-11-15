// XI-2, X14, B3, R6, X39
import { Badge } from "@access/ui/components/badge";
import { Item, ItemActions, ItemContent, ItemTitle } from "@access/ui/components/item";

import { text } from "./texts.js";

export type RungOwner =
  "access" | "executor" | "verifier" | "relay" | "pay" | "coordinator" | "requester";

export type RungState = "reached" | "not_reached" | "unknown" | "not_applicable";

export interface Rung {
  /** The rung's text key, e.g. `ladder.allowed`. */
  readonly text: string;
  readonly owner: RungOwner;
  readonly state: RungState;
}

export interface StatusLadderProps {
  /** The six rungs, in order, as their owners reported them; the ladder never merges two. */
  readonly rungs: readonly Rung[];
  readonly catalogue?: Readonly<Record<string, string>>;
}

/** The honest status ladder: one row per rung, each with its owner badge and its state in words,
 * never in colour or an icon alone. */
export function StatusLadder({ rungs, catalogue }: StatusLadderProps) {
  return (
    <ol
      className="access-ladder flex flex-col gap-2"
      aria-label={text("ladder.requested", catalogue)}
    >
      {rungs.map((r) => (
        <Item
          key={r.text}
          render={<li />}
          variant="outline"
          size="sm"
          className="access-ladder-rung"
          data-state={r.state}
        >
          <ItemContent>
            <ItemTitle className="access-ladder-step">{text(r.text, catalogue)}</ItemTitle>
          </ItemContent>{" "}
          <ItemActions>
            <Badge variant="outline" className="access-owner-badge">
              {text(`owner.${r.owner}`, catalogue)}
            </Badge>{" "}
            <span className="access-ladder-state text-sm text-muted-foreground">
              {text(`state.${r.state}`, catalogue)}
            </span>
          </ItemActions>
        </Item>
      ))}
    </ol>
  );
}
