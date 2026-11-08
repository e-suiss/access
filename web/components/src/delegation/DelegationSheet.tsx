// §8.5 S1, §8.17.5.1, §8.17.4.3, §9.9, §9.14.1 B, X3, X9, X27, X32, XI-4, XI-7
import {
  type Draft,
  type GiveRequest,
  type Opener,
  type Viewer,
  giveRequest,
  mayOpen,
  preview,
} from "./model.js";

const TITLES: Readonly<Record<string, string>> = {
  to: "To",
  can_do: "Can do",
  acting_as: "Acting as",
  can_pass_on: "Can pass on",
  limits: "Limits",
  requires: "Requires",
  valid: "Valid",
  not_included: "Not included",
  interpretation: "Interpretation",
};

export interface DelegationSheetProps {
  readonly draft: Draft;
  readonly viewer: Viewer;
  readonly nowMs: number;
  /** Who asked for the sheet (XI-7): only the viewer, or a Needs Attention item, opens it. */
  readonly openedBy: Opener;
  /** A third-party app's request (§8.17.4.3, X27): the title is "Connect *App*". */
  readonly app?: string;
  /** Changes an existing delegation (`grant.amend`). */
  readonly amend?: boolean;
  /** The Exercise this exact preview compiles to; the host signs and commits it. */
  readonly onGive: (r: GiveRequest) => void;
  readonly onCancel: () => void;
  /** After the commit was recorded. */
  readonly created?: boolean;
}

/** The S1 Delegation sheet: the exact typed preview with every mandatory block, the fields
 * outside the viewer's authority marked, and one "Give access" that hands back exactly what was
 * shown. There is no scope list and no "Allow" or "Authorize" (X27). */
export function DelegationSheet(p: DelegationSheetProps) {
  if (!mayOpen(p.openedBy)) {
    return null;
  }
  const title = p.app === undefined ? "Give access" : `Connect ${p.app}`;
  if (p.created === true) {
    return (
      <section className="access-delegation" role="dialog" aria-label={title}>
        <h2>Delegation created</h2>
      </section>
    );
  }
  const pv = preview(p.draft, p.viewer, p.nowMs);
  const request = giveRequest(p.draft, p.viewer, p.nowMs, p.amend === true);
  return (
    <section className="access-delegation" role="dialog" aria-label={title}>
      <h2>{title}</h2>
      <dl>
        {pv.blocks
          .filter((b) => b.block !== "interpretation" || b.lines.length > 0)
          .map((b) => (
            <div key={b.block} className={`access-delegation-${b.block}`}>
              <dt>{TITLES[b.block]}</dt>
              {b.lines.map((l) => (
                <dd key={l}>{l}</dd>
              ))}
            </div>
          ))}
      </dl>
      {pv.blockers.length > 0 ? (
        <ul className="access-delegation-blockers" role="alert">
          {pv.blockers.map((b) => (
            <li key={b}>{b}</li>
          ))}
        </ul>
      ) : null}
      <button
        type="button"
        disabled={request === null}
        onClick={() => {
          if (request !== null) {
            p.onGive(request);
          }
        }}
      >
        Give access
      </button>
      <button type="button" onClick={p.onCancel}>
        Cancel
      </button>
    </section>
  );
}
