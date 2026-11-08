// §8.13, §13.8, G39, X26, HL-5, TI-8, XI-3
/** How far an authority-changing request got. */
export type Sent = "never" | "sent";

/** The path it takes: straight to Access, or through an intermediary that may have forwarded it. */
export type Path = "direct" | "mediated";

/** What came back. */
export type Answer =
  | { readonly kind: "nothing" }
  | { readonly kind: "recorded"; readonly allowed: boolean; readonly witnessPending: boolean }
  | { readonly kind: "busy" }
  | { readonly kind: "no_time" }
  | { readonly kind: "absent" };

export interface Attempt {
  readonly sent: Sent;
  readonly path: Path;
  readonly answer: Answer;
  readonly timedOut: boolean;
  /** When the signed intent stops being valid, Unix ms. */
  readonly validUntil: number;
}

/** The text key the surface shows. */
export type Shown =
  | "outcome.submitted"
  | "outcome.confirmed"
  | "outcome.witness_pending"
  | "outcome.not_allowed"
  | "outcome.not_confirmed_checking"
  | "outcome.not_recorded"
  | "outcome.couldnt_reach"
  | "outcome.busy_retry"
  | "outcome.unavailable_time_check";

export type Next = "wait" | "retry_same_nonce" | "query_outcome" | "done" | "may_retry_new";

/** What `a` shows: nothing is done before Access recorded it, and an unknown outcome is never
 * shown as done or as not recorded. */
export function shown(a: Attempt): Shown {
  switch (a.answer.kind) {
    case "recorded":
      if (!a.answer.allowed) return "outcome.not_allowed";
      return a.answer.witnessPending ? "outcome.witness_pending" : "outcome.confirmed";
    case "busy":
      return "outcome.busy_retry";
    case "no_time":
      return "outcome.unavailable_time_check";
    case "absent":
      return "outcome.not_recorded";
    case "nothing":
      if (!a.timedOut) return "outcome.submitted";
      return a.sent === "never" && a.path === "direct"
        ? "outcome.couldnt_reach"
        : "outcome.not_confirmed_checking";
  }
}

/** What comes after `a` at `now`: the same nonce again while the intent is valid, then only the
 * outcome read. */
export function next(a: Attempt, now: number): Next {
  switch (shown(a)) {
    case "outcome.confirmed":
    case "outcome.witness_pending":
    case "outcome.not_allowed":
      return "done";
    case "outcome.submitted":
      return "wait";
    case "outcome.not_confirmed_checking":
      return now < a.validUntil ? "retry_same_nonce" : "query_outcome";
    case "outcome.not_recorded":
    case "outcome.couldnt_reach":
    case "outcome.busy_retry":
    case "outcome.unavailable_time_check":
      return "may_retry_new";
  }
}

/** What an ADP evaluation answer tells about a commit: a decision with its `ExerciseID` was
 * recorded; 429 and a 503 without a time source recorded nothing; anything else is unknown. */
export function answerOf(status: number, body: unknown): Answer {
  const b = (typeof body === "object" && body !== null ? body : {}) as {
    decision?: unknown;
    context?: { exercise?: unknown };
    reason?: unknown;
  };
  if (status === 200 && typeof b.decision === "boolean" && b.context?.exercise !== undefined) {
    return { kind: "recorded", allowed: b.decision, witnessPending: false };
  }
  if (status === 429) return { kind: "busy" };
  if (status === 503 && b.reason === "time") return { kind: "no_time" };
  return { kind: "nothing" };
}
