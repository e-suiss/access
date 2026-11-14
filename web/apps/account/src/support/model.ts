// OP-157 m.3 (f), §8.16, XI-17: what the Frontend API answers about support access, and whose
// action an Activity row of a support Grant is.
import { frontend, json } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import type { Drafted } from "./sign.js";

export interface Give extends Drafted {
  readonly template: string;
  readonly until: string;
  /** TN-137 (2): the same view access for a day, on a view request. */
  readonly standing?: Give;
}

export interface SupportRow {
  readonly id: string;
  readonly state: string;
  readonly operator: string;
  readonly organization: string;
  readonly case: string;
  readonly what: string;
  readonly minutes: number;
  readonly read_only: boolean;
  readonly until?: string;
  readonly ended_at?: string;
  readonly basis?: { readonly holding: { readonly grant: string } };
  readonly give?: Give;
  readonly revoke?: Drafted;
}

export interface Requests {
  readonly requests: readonly SupportRow[];
  readonly blocked: boolean;
}

export interface Access {
  readonly access: readonly SupportRow[];
  readonly blocked: boolean;
}

/** The support access the person gave; empty when it can't be read: the rows then just name no
 * operator, they never name the person instead. */
export async function supportAccess(): Promise<readonly SupportRow[]> {
  try {
    return (await json<Access>(frontend("/v1/me/support-access"))).access;
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
