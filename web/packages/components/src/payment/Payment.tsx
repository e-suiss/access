// OP-156 m.3 (u), (v), §8.11, §8.17.5.11, §8.17.7.2, XI-14, XI-17, X30, E26, R8, X8, INV-20
// The payment renderers a merchant, Pay or a third-party app embeds: the limit rows of a Grant
// with their owners, the one-time payment, "save my card", a merchant that can charge the
// viewer, and Pay's agreements and consents linked to the delegation they rest on. They show
// what Access and Pay reported and hand requests back; they sign and decide nothing.
import { text } from "../texts.js";
import { type Line, type LimitRow, type Money, money } from "./model.js";

type Catalogue = Readonly<Record<string, string>> | undefined;

/** The text of `line`, its values placed as plain text (TN-131). */
export function say(line: Line, catalogue?: Catalogue): string {
  let out = text(line.text, catalogue);
  for (const [name, value] of Object.entries(line.args ?? {})) {
    out = out.replaceAll(`{ $${name} }`, value);
  }
  return out;
}

export interface LimitRowsProps {
  readonly rows: readonly LimitRow[];
  readonly catalogue?: Catalogue;
}

/** XI-14: one row per limit, each under its owner's badge. */
export function LimitRows({ rows, catalogue }: LimitRowsProps) {
  if (rows.length === 0) return null;
  return (
    <ul className="access-limits">
      {rows.map((r, i) => (
        <li key={`${r.owner}:${String(i)}`} data-owner={r.owner}>
          <span className="access-owner-badge">{say({ text: `owner.${r.owner}` }, catalogue)}</span>{" "}
          {say(r.line, catalogue)}
        </li>
      ))}
    </ul>
  );
}

/** "Pay 300 TRY to M, once", as the Kernel decoded it (`pay.oneTimeOf`). */
export interface OneTime {
  readonly amount: Money;
  readonly recipient: string;
  readonly purpose: string;
  readonly until: number;
}

export interface OneTimePaymentProps {
  /** The decoded payment, or why the request is not a one-time payment. */
  readonly payment: OneTime | string;
  /** How the recipient is named to the viewer. */
  readonly merchant: string;
  readonly locale: string;
  readonly onPay: () => void;
  readonly onCancel: () => void;
  /** While the payment is being sent. */
  readonly busy?: boolean;
  readonly catalogue?: Catalogue;
}

/** The one-time payment (§8.17.5.11): the exact amount, recipient and purpose, a separate verb
 * from letting a merchant charge again. A request that is not one-time cannot be paid here. */
export function OneTimePayment({
  payment,
  merchant,
  locale,
  onPay,
  onCancel,
  busy,
  catalogue,
}: OneTimePaymentProps) {
  const title = say({ text: "payment.one_time_title" }, catalogue);
  if (typeof payment === "string") {
    return (
      <section className="access-payment" aria-label={title}>
        <h3>{title}</h3>
        <p role="alert" data-refused={payment}>
          {say({ text: "payment.not_one_time", args: { merchant } }, catalogue)}
        </p>
        <button type="button" className="secondary" onClick={onCancel}>
          {say({ text: "action.cancel" }, catalogue)}
        </button>
      </section>
    );
  }
  return (
    <section className="access-payment" aria-label={title}>
      <h3>{title}</h3>
      <p data-testid="one-time">
        {say(
          {
            text: "payment.one_time_confirm",
            args: { amount: money(payment.amount, locale), merchant },
          },
          catalogue,
        )}
      </p>
      <p className="meta">
        {say({ text: "payment.purpose", args: { purpose: payment.purpose } }, catalogue)}
      </p>
      <div className="actions">
        <button type="button" onClick={onPay} disabled={busy === true}>
          {say({ text: "payment.pay" }, catalogue)}
        </button>
        <button type="button" className="secondary" onClick={onCancel}>
          {say({ text: "action.cancel" }, catalogue)}
        </button>
      </div>
    </section>
  );
}

export interface SaveCardProps {
  readonly merchant: string;
  readonly perOrder: Money;
  /** When the Grant ends, as the viewer reads it. */
  readonly until: string;
  readonly locale: string;
  readonly onConfirm: () => void;
  readonly onCancel: () => void;
  readonly catalogue?: Catalogue;
}

/** "Save my card" (S1 end-customer profile): letting the merchant charge again is its own verb
 * and its own preview, apart from paying once. */
export function SaveCard({
  merchant,
  perOrder,
  until,
  locale,
  onConfirm,
  onCancel,
  catalogue,
}: SaveCardProps) {
  return (
    <section className="access-save-card">
      <p data-testid="save-card">
        {say(
          {
            text: "merchants.save_card",
            args: { merchant, amount: money(perOrder, locale), time: until },
          },
          catalogue,
        )}
      </p>
      <div className="actions">
        <button type="button" onClick={onConfirm}>
          {say({ text: "merchants.save_card_confirm", args: { merchant } }, catalogue)}
        </button>
        <button type="button" className="secondary" onClick={onCancel}>
          {say({ text: "action.cancel" }, catalogue)}
        </button>
      </div>
    </section>
  );
}

/** One of Pay's own objects resting on the delegation: a payment agreement or a scheme consent,
 * as Pay names it and links it. Pay's to show and to cancel. */
export interface PayObject {
  readonly kind: "agreement" | "consent";
  /** Pay's own label, e.g. "SEPA mandate MR-221". */
  readonly label: string;
  /** Where Pay shows it; dropped unless `https`. */
  readonly href?: string;
}

/** A merchant that can charge the viewer (S2). */
export interface Merchant {
  readonly grant: string;
  readonly name: string;
  /** The holder is the merchant's agent (X30). */
  readonly agent: boolean;
  readonly limits: readonly LimitRow[];
  /** Pay's objects that rest on this delegation; separate rows, separately cancelled. */
  readonly pay?: readonly PayObject[];
}

function https(href: string | undefined): string | undefined {
  if (href === undefined) return undefined;
  try {
    const u = new URL(href);
    return u.protocol === "https:" ? u.toString() : undefined;
  } catch {
    return undefined;
  }
}

export interface MerchantsProps {
  readonly merchants: readonly Merchant[];
  /** Asks the host to revoke the merchant's Grant (`grant.revoke`). */
  readonly onStop: (grant: string) => void;
  readonly catalogue?: Catalogue;
}

/** "Merchants that can charge you" (S2, §8.11, §8.17.7.2): Access's delegation and Pay's
 * agreements are separate rows with separate actions; the merchant's agent is shown as an
 * agent, never as a person; what the merchant decides inside its business is not shown (E26). */
export function Merchants({ merchants, onStop, catalogue }: MerchantsProps) {
  const title = say({ text: "merchants.title" }, catalogue);
  return (
    <section className="access-merchants" aria-label={title}>
      <h3>{title}</h3>
      {merchants.length === 0 && <p>{say({ text: "merchants.none" }, catalogue)}</p>}
      <ul className="rows">
        {merchants.map((m) => {
          const limit = m.limits.find((l) => l.owner === "access")?.line.args?.["limit"] ?? "";
          return (
            <li key={m.grant} className="row" data-grant={m.grant}>
              <p>
                <strong>{m.name}</strong>
                {m.agent && (
                  <>
                    {" · "}
                    <span className="access-agent-badge" data-party-kind="agent">
                      {say(
                        { text: "merchants.agent_badge", args: { merchant: m.name } },
                        catalogue,
                      )}
                    </span>
                  </>
                )}
              </p>
              <LimitRows rows={m.limits} catalogue={catalogue} />
              <button
                type="button"
                onClick={() => {
                  onStop(m.grant);
                }}
              >
                {say({ text: "merchants.stop" }, catalogue)}
              </button>
              {(m.pay ?? []).length > 0 && (
                <ul className="access-pay-objects" data-owner="pay">
                  {(m.pay ?? []).map((o) => {
                    const href = https(o.href);
                    const line =
                      o.kind === "agreement"
                        ? say(
                            {
                              text: "merchants.based_on",
                              args: { agreement: o.label, merchant: m.name, limit },
                            },
                            catalogue,
                          )
                        : say(
                            {
                              text: "merchants.scheme_consent",
                              args: { consent: o.label, merchant: m.name },
                            },
                            catalogue,
                          );
                    return (
                      <li key={`${o.kind}:${o.label}`}>
                        {line}
                        {href !== undefined && (
                          <>
                            {" · "}
                            <a href={href}>{say({ text: "merchants.agreement" }, catalogue)}</a>
                          </>
                        )}
                      </li>
                    );
                  })}
                  <li className="meta">
                    {say({ text: "merchants.cancel_separately" }, catalogue)}
                  </li>
                </ul>
              )}
              <p className="meta">
                {say({ text: "merchants.not_explained", args: { merchant: m.name } }, catalogue)}
              </p>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
