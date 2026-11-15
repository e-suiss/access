// OP-158 m.3 (e), (t), XI-20, X14, X26, §6.4, §8.7, §8.13
// `<DegradedNotice />`: a failure with its owner, what is UNKNOWN, what is missing and the
// fail-closed default that holds until then. `<RevocationStatus />`: a recorded revocation reads
// "Revoked — confirming (witness pending)" until `witnessed_through` covers it. Neither decides
// anything; both show what Access reported.
import { Alert } from "@access/ui/components/alert";
import { Badge } from "@access/ui/components/badge";

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
    <Alert className="access-degraded gap-1" role="status" data-failure={state.id}>
      <p data-testid="degraded-owner" className="font-semibold">
        {say({ text: "degraded.owner", args: { owner } }, catalogue)}
      </p>
      <p data-testid="degraded-unknown">
        <strong>{say({ text: "degraded.unknown" }, catalogue)}</strong>
      </p>
      <p data-testid="degraded-missing" className="text-sm text-muted-foreground">
        {say({ text: "degraded.missing", args: { what: state.missing } }, catalogue)}
      </p>
      <p data-testid="degraded-default" className="text-sm text-muted-foreground">
        {say({ text: "degraded.safe_default", args: { default: state.safeDefault } }, catalogue)}
      </p>
    </Alert>
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
    <Badge
      variant="outline"
      className="access-revocation"
      role="status"
      data-message-id={key}
      data-state={done ? "witnessed" : "pending"}
    >
      {say({ text: key }, catalogue)}
    </Badge>
  );
}
