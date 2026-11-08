// XI-2, X14, B3, R6, X39
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
    <ol className="access-ladder" aria-label={text("ladder.requested", catalogue)}>
      {rungs.map((r) => (
        <li key={r.text} className="access-ladder-rung" data-state={r.state}>
          <span className="access-ladder-step">{text(r.text, catalogue)}</span>{" "}
          <span className="access-owner-badge">{text(`owner.${r.owner}`, catalogue)}</span>{" "}
          <span className="access-ladder-state">{text(`state.${r.state}`, catalogue)}</span>
        </li>
      ))}
    </ol>
  );
}
