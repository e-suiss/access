// OP-156 m.3 (t), §8.17.6.1, §8.17.6.5, §8.17.7.2, IA-1, IA-3, X5–X7
// The Work seam's renderers: the Work badge, the "Ends with Work commitment X" link of an
// inventory row, the hub's one "N approvals waiting for you →" link and the honest line of an
// approval whose Gate is not updated yet. They show what Access and the coordinator reported
// and decide nothing: a Gate cleared is never shown as allowed.
import { text } from "../texts.js";

/** The coordinator's Needs Attention link, as the hub's `attention` carries it. */
export interface Attention {
  readonly href: string;
  readonly count: number;
}

export interface WorkTextsProps {
  /** The host's catalogue; English otherwise. */
  readonly catalogue?: Readonly<Record<string, string>> | undefined;
}

function say(
  key: string,
  catalogue: WorkTextsProps["catalogue"],
  args: Readonly<Record<string, string>> = {},
): string {
  let out = text(key, catalogue);
  for (const [name, value] of Object.entries(args)) out = out.replaceAll(`{ $${name} }`, value);
  return out;
}

/** An `https` URL, or nothing: a coordinator link never runs script. */
export function safeHref(href: string): string | undefined {
  try {
    const u = new URL(href);
    return u.protocol === "https:" ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

/** The owner badge of a Work-owned line (IA-3). */
export function WorkBadge({ catalogue }: WorkTextsProps) {
  return <span className="access-work-badge">{say("work.badge", catalogue)}</span>;
}

export interface CommitmentLinkProps extends WorkTextsProps {
  /** The `CommitmentRef` as the coordinator names it. */
  readonly commitment: string;
  /** Where the coordinator shows it; the link is dropped unless it is `https`. */
  readonly href?: string;
}

/** "Ends with Work commitment X" on an inventory row (§8.17.7.2). */
export function CommitmentLink({ commitment, href, catalogue }: CommitmentLinkProps) {
  const label = say("work.ends_with_commitment", catalogue, { commitment });
  const target = href === undefined ? undefined : safeHref(href);
  return (
    <span className="access-work-commitment">
      <WorkBadge catalogue={catalogue} />{" "}
      {target === undefined ? label : <a href={target}>{label}</a>}
    </span>
  );
}

export interface AttentionLinkProps extends WorkTextsProps {
  readonly attention?: Attention;
}

/** The hub's one link to the coordinator's queue; Access keeps no queue of its own (IA-1). */
export function AttentionLink({ attention, catalogue }: AttentionLinkProps) {
  if (attention === undefined || attention.count < 1) return null;
  const target = safeHref(attention.href);
  if (target === undefined) return null;
  return (
    <a className="access-work-attention" href={target}>
      {say("attention.approvals_waiting", catalogue, { count: String(attention.count) })}
    </a>
  );
}

export interface GateStatusProps extends WorkTextsProps {
  /** Whether Access recorded the contribution. */
  readonly recorded: boolean;
  /** Whether the coordinator registered its Declaration. */
  readonly gateUpdated: boolean;
}

/** The honest line after one ceremony (§8.17.6.1): never "approved and proceeding". */
export function GateStatus({ recorded, gateUpdated, catalogue }: GateStatusProps) {
  if (!recorded || gateUpdated) return null;
  return <p className="access-work-gate">{say("work.gate_not_updated", catalogue)}</p>;
}
