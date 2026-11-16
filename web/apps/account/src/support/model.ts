// OP-157 m.3 (f), §8.16, XI-17: what the Frontend API answers about support access, and whose
// action an Activity row of a support Grant is.
import * as v from "valibot";

import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";

const Drafted = v.object({
  payload: v.string(),
  intent: v.string(),
  basis: v.object({ anchor: v.string() }),
  pep: v.string(),
});
type Drafted = v.InferOutput<typeof Drafted>;

export interface Give extends Drafted {
  readonly template: string;
  readonly until: string;
  /** TN-137 (2): the same view access for a day, on a view request. */
  readonly standing?: Give | undefined;
}

const Give: v.GenericSchema<Give> = v.object({
  ...Drafted.entries,
  template: v.string(),
  until: v.string(),
  standing: v.optional(v.lazy(() => Give)),
});

const SupportRow = v.object({
  id: v.string(),
  state: v.string(),
  operator: v.string(),
  organization: v.string(),
  case: v.string(),
  what: v.string(),
  minutes: v.number(),
  read_only: v.boolean(),
  until: v.optional(v.string()),
  ended_at: v.optional(v.string()),
  basis: v.optional(v.object({ holding: v.object({ grant: v.string() }) })),
  give: v.optional(Give),
  revoke: v.optional(Drafted),
});
export type SupportRow = v.InferOutput<typeof SupportRow>;

export const Requests = v.object({ requests: v.array(SupportRow), blocked: v.boolean() });
export type Requests = v.InferOutput<typeof Requests>;

export const Access = v.object({ access: v.array(SupportRow), blocked: v.boolean() });
export type Access = v.InferOutput<typeof Access>;

/** The support access the person gave. */
export function readAccess(): Promise<Access> {
  return json(frontend("/v1/me/support-access"), Access);
}

/** The support access the person gave; empty when it can't be read: the rows then just name no
 * operator, they never name the person instead. */
export async function supportAccess(): Promise<readonly SupportRow[]> {
  try {
    return (await readAccess()).access;
  } catch {
    return [];
  }
}

/** The Activity line of a use on Grant `grant`, when that is support access the person gave:
 * the action is the operator's, shown only in the person's own view (§8.16, XI-17). */
export function supportLine(
  grant: string | undefined,
  access: readonly SupportRow[],
  time: string,
): string | undefined {
  const row = access.find((a) => a.basis?.holding.grant === grant);
  if (grant === undefined || row === undefined) return undefined;
  return t("activity.support_by", {
    action: t(row.read_only ? "activity.support_viewed" : "activity.support_acted"),
    operator: row.operator,
    organization: row.organization,
    time,
  });
}
