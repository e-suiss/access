// OP-156 m.3 (v), §18.3, §18.8.1 H5, §8.13, §8.17.7.2, XI-1, XI-5, XI-10, XI-11, XI-14, XI-16,
// IA-1, INV-24
// `<DelegationPage />`: the delegation page One, Work, Pay and third-party agent apps embed. It
// renders the experience service's hub (`/experience/v1/hub`) as is: every row with its owner,
// capacity, status and limits (Access's authority limit and Pay's financial limit as two rows),
// the notices Access and Relay gave, and the one link to the coordinator's queue. Revoke goes
// back to the host, which sends the viewer's own signed Exercise; this page decides nothing.
import { type Attention, AttentionLink } from "../work/Work.js";
import { type LimitRow, type PayLimit, limitRows } from "../payment/model.js";
import { LimitRows, say } from "../payment/Payment.js";

type Catalogue = Readonly<Record<string, string>> | undefined;

/** One limit of a row as the hub carries it (XI-14). */
export interface HubLimit {
  readonly kind: "authority" | "financial";
  readonly owner: string;
  readonly term: unknown;
  readonly as_of?: number;
}

/** One holding row as the hub carries it. */
export interface HubRow {
  readonly grant: string;
  readonly owner: string;
  readonly status: string;
  readonly who: { readonly kind: string; readonly party?: string };
  readonly source?: { readonly text: string; readonly issuer: string };
  readonly capacity: readonly { readonly text: string; readonly party?: string }[];
  readonly what: readonly string[];
  readonly validity: { readonly valid_until: number };
  readonly limits: readonly HubLimit[];
  readonly offers: readonly {
    readonly action: string;
    readonly available: boolean;
    readonly who_can?: string;
  }[];
}

/** The hub as `/experience/v1/hub` answers it. */
export interface HubView {
  readonly as_of: number;
  readonly acting_for_you: readonly HubRow[];
  readonly shared_from_you: readonly HubRow[];
  readonly your_authority: readonly HubRow[];
  readonly notices: readonly string[];
  readonly attention?: Attention;
}

/** Pay's `pay-limit` term of a financial limit, as the hub carries it. */
function payLimit(term: unknown): PayLimit | undefined {
  if (typeof term !== "object" || term === null) return undefined;
  const t = term as Readonly<Record<string, unknown>>;
  const { currency, limit_minor: limit, period, held_minor: held } = t;
  if (typeof currency !== "string" || typeof limit !== "number") return undefined;
  if (period !== "transaction" && period !== "day" && period !== "month") return undefined;
  return {
    limit: { currency, minor: limit },
    period,
    ...(typeof held === "number" ? { held: { currency, minor: held } } : {}),
  };
}

/** XI-14: Access's limits and Pay's limits of one row, each from its own owner's term. */
export function rowLimits(row: HubRow, locale: string, catalogue?: Catalogue): LimitRow[] {
  const authority = row.limits.filter((l) => l.kind === "authority" && l.owner === "access");
  const financial = row.limits
    .filter((l) => l.kind === "financial" && l.owner === "pay")
    .map((l) => payLimit(l.term))
    .filter((p): p is PayLimit => p !== undefined);
  return limitRows(
    authority.map((l) => l.term),
    financial,
    locale,
    (p) => say({ text: `period.${p}` }, catalogue),
  );
}

export interface DelegationPageProps {
  readonly hub: HubView;
  /** How a Party is named to the viewer. */
  readonly name: (party: string) => string;
  /** A time as the viewer reads it. */
  readonly time: (ms: number) => string;
  readonly locale: string;
  /** Asks the host to revoke `grant` with the viewer's own signed Exercise. */
  readonly onRevoke?: (grant: string) => void;
  readonly catalogue?: Catalogue;
}

const SECTIONS = [
  ["your_authority", "hub.your_authority"],
  ["acting_for_you", "hub.acting_for_you"],
  ["shared_from_you", "hub.shared_from_you"],
] as const;

/** The embedded delegation page (§18.3, §18.8.1 H5). */
export function DelegationPage({
  hub,
  name,
  time,
  locale,
  onRevoke,
  catalogue,
}: DelegationPageProps) {
  return (
    <div className="access-delegation-page">
      {hub.notices.map((n) => (
        <p
          key={n}
          className="notice"
          role={n === "status.access_unavailable" ? "alert" : undefined}
        >
          {say({ text: n }, catalogue)}
        </p>
      ))}
      {hub.attention !== undefined && (
        <AttentionLink attention={hub.attention} catalogue={catalogue} />
      )}
      {SECTIONS.map(([key, title]) => (
        <section key={key} aria-label={say({ text: title }, catalogue)} data-section={key}>
          <h3>{say({ text: title }, catalogue)}</h3>
          <ul className="rows">
            {hub[key].map((r) => {
              const revoke = r.offers.find((o) => o.action === "revoke");
              return (
                <li key={r.grant} className="row" data-grant={r.grant}>
                  <p>
                    <span className="access-owner-badge">
                      {say({ text: `owner.${r.owner}` }, catalogue)}
                    </span>{" "}
                    {r.who.party === undefined ? r.who.kind : name(r.who.party)} ·{" "}
                    <span className="mono">{r.what.join(", ")}</span> ·{" "}
                    {r.capacity
                      .map((c) =>
                        say(
                          {
                            text: c.text,
                            args: { party: c.party === undefined ? "" : name(c.party) },
                          },
                          catalogue,
                        ),
                      )
                      .join(" · ")}
                  </p>
                  {r.source !== undefined && (
                    <p className="meta" data-testid="source">
                      {say(
                        { text: r.source.text, args: { issuer: name(r.source.issuer) } },
                        catalogue,
                      )}
                    </p>
                  )}
                  <p className="meta">
                    {say({ text: r.status }, catalogue)} ·{" "}
                    {say(
                      {
                        text: "validity.valid_until",
                        args: { time: time(r.validity.valid_until) },
                      },
                      catalogue,
                    )}
                  </p>
                  <LimitRows rows={rowLimits(r, locale, catalogue)} catalogue={catalogue} />
                  {revoke?.available === true && onRevoke !== undefined ? (
                    <button
                      type="button"
                      onClick={() => {
                        onRevoke(r.grant);
                      }}
                    >
                      {say({ text: "action.revoke" }, catalogue)}
                    </button>
                  ) : (
                    revoke?.who_can !== undefined && (
                      <span className="meta">{say({ text: revoke.who_can }, catalogue)}</span>
                    )
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </div>
  );
}
