// OP-153 m.3 (s), §8.8
/** English text of each key the components and the experience emit; the host passes its own
 * catalogue (Fluent) to replace any of them. */
export const EN: Readonly<Record<string, string>> = {
  "ladder.requested": "Requested",
  "ladder.approval_recorded": "Approval recorded",
  "ladder.gate_satisfied": "Gate satisfied",
  "ladder.allowed": "Allowed",
  "ladder.not_allowed": "Not allowed",
  "ladder.decision_unknown": "Decision not known yet",
  "ladder.started": "Started",
  "ladder.reported_done": "Reported done",
  "ladder.reported_not_done": "Reported not done",
  "ladder.reported_unknown": "Unknown — not reported",
  "ladder.reported_differs": "Reported differently from what was allowed",
  "state.reached": "yes",
  "state.not_reached": "no",
  "state.unknown": "not reported",
  "state.not_applicable": "not part of this",
  "owner.access": "Access",
  "owner.executor": "Runtime",
  "owner.verifier": "Verifier",
  "owner.relay": "Relay",
  "owner.pay": "Pay",
  "owner.coordinator": "Coordinator",
  "owner.requester": "Requester",
  "why.derived": "From the decision record",
  "why.advisory": "Advisory — not recorded",
  "why.past": "As decided at that time",
  "why.hypothetical": "If asked now",
  "why.could_change": "What could change this",
  "why.depth.default": "Summary",
  "why.depth.expert": "Details",
  "why.depth.audit": "Audit",
  "stepup.title": "Confirm it's you",
  "stepup.start": "Continue",
  "stepup.cancel": "Cancel",
  "outcome.submitted": "Submitted",
  "outcome.confirmed": "Done",
  "outcome.not_allowed": "Not allowed",
  "outcome.not_confirmed_checking": "Not confirmed — checking",
  "outcome.witness_pending": "Recorded — witness pending",
  "outcome.not_recorded": "Not recorded — try again",
  "outcome.couldnt_reach": "Couldn't reach Access. Your request was not recorded.",
  "outcome.busy_retry": "Busy — retry",
  "outcome.unavailable_time_check": "Unavailable — time check",
};

/** Looks `key` up in `catalogue`, then in English; an unknown key shows as itself. */
export function text(key: string, catalogue?: Readonly<Record<string, string>>): string {
  return catalogue?.[key] ?? EN[key] ?? key;
}
