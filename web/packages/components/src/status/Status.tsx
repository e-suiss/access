// OP-158 m.3 (e), (t), XI-20, X14, X26, §6.4, §8.7, §8.13
// `<DegradedNotice />`: a failure with its owner, what is UNKNOWN, what is missing and the
// fail-closed default that holds until then. `<RevocationStatus />`: a recorded revocation reads
// "Revoked — confirming (witness pending)" until `witnessed_through` covers it. Neither decides
// anything; both show what Access reported.
import { say } from "../payment/Payment.js";
import { type Degraded, type Recorded, witnessed } from "./model.js";

type Catalogue = Readonly<Record<string, string>> | undefined;

export interface DegradedNoticeProps {
  readonly state: Degraded;
  readonly catalogue?: Catalogue;
}

/** XI-20: owner, UNKNOWN, missing information and the safe default, always all four. */
export function DegradedNotice({ state, catalogue }: DegradedNoticeProps) {
  const owner = say({ text: `owner.${state.owner}` }, catalogue);
  return (
    <section className="access-degraded" role="status" data-failure={state.id}>
      <p data-testid="degraded-owner">
        {say({ text: "degraded.owner", args: { owner } }, catalogue)}
      </p>
      <p data-testid="degraded-unknown">
        <strong>{say({ text: "degraded.unknown" }, catalogue)}</strong>
      </p>
      <p data-testid="degraded-missing">
        {say({ text: "degraded.missing", args: { what: state.missing } }, catalogue)}
      </p>
      <p data-testid="degraded-default">
        {say({ text: "degraded.safe_default", args: { default: state.safeDefault } }, catalogue)}
      </p>
    </section>
  );
}

export interface RevocationStatusProps {
  readonly recorded: Recorded;
  readonly catalogue?: Catalogue;
}

/** §8.7, X14: the qualifier stays until the acknowledgement covers the record. */
export function RevocationStatus({ recorded, catalogue }: RevocationStatusProps) {
  const done = witnessed(recorded);
  const key = done ? "outcome.confirmed" : "outcome.revoked_confirming";
  return (
    <span
      className="access-revocation"
      role="status"
      data-message-id={key}
      data-state={done ? "witnessed" : "pending"}
    >
      {say({ text: key }, catalogue)}
    </span>
  );
}
