// XI-17, A-12, §8.7, §8.13, §8.17.5.8, §8.17.7.4, §8.17.7.5, §8.17.11.1, §12.4.1, X8, X13,
// X30, XI-19, TN-133
import { text } from "../texts.js";
import {
  type AgentFace,
  type Connection,
  type Line,
  type OutcomeLine,
  type StopRow,
  type Suggestion,
  badge,
  connectionText,
} from "./model.js";

type Catalogue = Readonly<Record<string, string>> | undefined;

/** The text of `line` from `catalogue`, its values placed as plain text (TN-131). */
export function say(line: Line, catalogue?: Catalogue): string {
  let out = text(line.text, catalogue);
  for (const [name, value] of Object.entries(line.args ?? {})) {
    out = out.replaceAll(`{ $${name} }`, value);
  }
  return out;
}

export interface AgentBadgeProps {
  readonly face: AgentFace;
  /** How a Party is named to the viewer. */
  readonly name: (party: string) => string;
  readonly catalogue?: Catalogue;
}

/** XI-17: "Agent · Acting for X · operated by Y" wherever an agent appears; there is no person
 * badge for an agent. */
export function AgentBadge({ face, name, catalogue }: AgentBadgeProps) {
  return (
    <span className="access-agent-badge" data-party-kind="agent">
      {badge(face, name)
        .map((l) => say(l, catalogue))
        .join(" · ")}
    </span>
  );
}

export interface OutcomeLabelsProps {
  readonly lines: readonly OutcomeLine[];
  readonly name: (party: string) => string;
  readonly catalogue?: Catalogue;
}

/** What runtimes reported about a use, each with its reporter and evidence kind (§8.17.10.3);
 * an agent's own account of what it did is never shown as the outcome (X30). */
export function OutcomeLabels({ lines, name, catalogue }: OutcomeLabelsProps) {
  return (
    <ul className="access-outcomes">
      {lines.map((l, i) => (
        <li key={`${l.text}:${String(i)}`} data-outcome={l.text}>
          {say(
            { text: l.text, args: l.reporter === undefined ? {} : { reporter: name(l.reporter) } },
            catalogue,
          )}
          {l.evidence.length > 0 && (
            <span className="access-evidence">
              {" · "}
              {l.evidence.map((e) => text(e, catalogue)).join(", ")}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

export interface StopRowsProps {
  readonly rows: readonly StopRow[];
  readonly catalogue?: Catalogue;
}

/** "Stop" as two rows, each with its owner (§8.17.7.5, X13): never one "Stopped". */
export function StopRows({ rows, catalogue }: StopRowsProps) {
  return (
    <ul className="access-stop-rows">
      {rows.map((r) => (
        <li key={r.owner} data-owner={r.owner}>
          <span className="access-owner-badge">{text(`owner.${r.owner}`, catalogue)}</span>{" "}
          {say(r.line, catalogue)}
        </li>
      ))}
    </ul>
  );
}

export interface AgentConnectionsProps {
  readonly connections: readonly Connection[];
  readonly name: (party: string) => string;
  readonly time: (ms: number) => string;
  /** One click: the host sends `DELETE …/vault/connections/{connection}`. */
  readonly onDisconnect: (connection: string) => void;
  readonly catalogue?: Catalogue;
}

/** Which agent used which connected account, with a one-click Disconnect (§12.4.1, TN-133). It
 * shows no token and keeps no copy. */
export function AgentConnections({
  connections,
  name,
  time,
  onDisconnect,
  catalogue,
}: AgentConnectionsProps) {
  const title = text("agent_connections.title", catalogue);
  return (
    <section className="access-agent-connections" aria-label={title}>
      <h3>{title}</h3>
      {connections.length === 0 && <p>{text("agent_connections.empty", catalogue)}</p>}
      <ul>
        {connections.map((c) => (
          <li key={c.connection} data-connection={c.connection}>
            <p>
              <strong>{c.upstream}</strong> · {text(connectionText(c), catalogue)}
            </p>
            {c.scopes.length > 0 && <p className="access-scopes">{c.scopes.join(", ")}</p>}
            {c.used.length === 0 ? (
              <p>{text("agent_connections.not_used", catalogue)}</p>
            ) : (
              <ul>
                {c.used.map((u) => (
                  <li key={u.agent}>
                    <span className="access-agent-badge" data-party-kind="agent">
                      {text("agent.badge", catalogue)}
                    </span>{" "}
                    {say(
                      {
                        text:
                          u.atMs === undefined
                            ? "agent_connections.used_by"
                            : "agent_connections.used_by_at",
                        args: {
                          agent: name(u.agent),
                          ...(u.atMs === undefined ? {} : { time: time(u.atMs) }),
                        },
                      },
                      catalogue,
                    )}
                  </li>
                ))}
              </ul>
            )}
            {c.status !== "disconnected" && (
              <button
                type="button"
                onClick={() => {
                  onDisconnect(c.connection);
                }}
              >
                {text("action.disconnect", catalogue)}
              </button>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}

export interface DelegationSuggestionProps {
  readonly suggestion: Suggestion;
  readonly name: (party: string) => string;
  /** Opens the S1 exact preview; nothing is given before the viewer signs it there. */
  readonly onReview: (s: Suggestion) => void;
  readonly onDismiss: () => void;
  readonly catalogue?: Catalogue;
}

/** "You approved 6 similar requests… Give Agent A access…?" (§8.17.11.1, X8): a suggestion that
 * never takes effect by itself (XI-19). */
export function DelegationSuggestion({
  suggestion,
  name,
  onReview,
  onDismiss,
  catalogue,
}: DelegationSuggestionProps) {
  return (
    <section className="access-suggestion" aria-label={text("suggestion.title", catalogue)}>
      <p>
        {say(
          {
            text: "suggestion.repeated",
            args: {
              count: String(suggestion.count),
              agent: name(suggestion.agent),
              action: suggestion.action,
            },
          },
          catalogue,
        )}
      </p>
      <p className="access-note">{text("suggestion.not_applied", catalogue)}</p>
      <button
        type="button"
        onClick={() => {
          onReview(suggestion);
        }}
      >
        {text("action.review_delegation", catalogue)}
      </button>
      <button type="button" onClick={onDismiss}>
        {text("action.not_now", catalogue)}
      </button>
    </section>
  );
}
