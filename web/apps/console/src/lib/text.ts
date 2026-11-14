// §8.17.8, §8.17.9.2, §8.10, X24: the sentences the console builds from structured answers. A
// reason is shown by its class only (E-4): no policy content, thresholds or statement bodies are
// rendered, whatever an answer carries. An unknown subcode reads as its class (P15).
import { reason as sdkReason } from "@esuiss/access";

import { t, type Key } from "../i18n/index.js";

/** The category text and "what is needed" of each reason class (§8.17.8.2, E-6). */
export const REASONS: Readonly<Record<sdkReason.ReasonClass, readonly [Key, Key]>> = {
  "no-covering-authority": ["reasonNoCovering", "reasonNoCoveringFix"],
  "outside-instance-limits": ["reasonOutsideLimits", "reasonOutsideLimitsFix"],
  restricted: ["reasonRestricted", "reasonRestrictedFix"],
  "budget-exhausted": ["reasonBudget", "reasonBudgetFix"],
  ended: ["reasonGrantEnded", "reasonEndedFix"],
  "capacity-mismatch": ["reasonCapacity", "reasonCapacityFix"],
  "source-not-accepted": ["reasonSourceNotAccepted", "reasonSourceNotAcceptedFix"],
  "schema-not-accepted": ["reasonSchemaNotAccepted", "reasonSchemaNotAcceptedFix"],
  "nonce-closed": ["reasonNonce", "reasonNonceFix"],
  "foreign-status-unavailable": ["reasonForeign", "reasonForeignFix"],
};

/** One blocker as shown: its class's text and what is needed; `undefined` for a malformed one. */
export function blockerText(
  b: unknown,
): { readonly what: string; readonly fix: string } | undefined {
  if (typeof b !== "object" || b === null) return undefined;
  const { class: c, subcode } = b as { class?: unknown; subcode?: unknown };
  if (typeof c !== "string") return undefined;
  try {
    const r = sdkReason.reason(c, typeof subcode === "string" ? subcode : undefined);
    const [what, fix] = REASONS[r.class];
    return { what: t(what), fix: t(fix) };
  } catch {
    return undefined;
  }
}

/** The relation words of a change-impact answer. */
export function relationKey(relation: string): Key {
  switch (relation) {
    case "equivalent":
      return "relationEquivalent";
    case "narrowing":
      return "relationNarrowing";
    case "widening":
      return "relationWidening";
    case "incomparable":
      return "relationIncomparable";
    case "may_error":
      return "relationMayError";
    default:
      return "relationUnknown";
  }
}

export interface Ability {
  readonly ability: {
    readonly action: unknown;
    readonly bounds?: unknown;
  };
  readonly holders_gaining: number;
  readonly holders_losing: number;
}

/** An ability's name: the action's `namespace.name`, as the answer gives it. */
export function abilityName(a: Ability): string {
  const act = a.ability.action as { namespace?: unknown; name?: unknown } | null;
  if (act !== null && typeof act === "object") {
    const ns = typeof act.namespace === "string" ? act.namespace : "";
    const name = typeof act.name === "string" ? act.name : "";
    if (ns !== "" || name !== "") return ns === "" ? name : `${ns}.${name}`;
  }
  return JSON.stringify(a.ability.action);
}

/**
 * §8.17.9.2: "Moving 3 role delegations to v5 gives 41 people a new ability: *refund > 5,000
 * TRY*; removes 1 ability from 12 people." A count that is only an upper bound says so.
 */
export function impactSentence(
  moves: number,
  to: number,
  abilities: readonly Ability[],
  upperBound: boolean,
): string {
  const people = (n: number) => (upperBound ? t("atMost", { n: String(n) }) : String(n));
  const parts: string[] = [];
  for (const a of abilities) {
    if (a.holders_gaining > 0) {
      parts.push(t("impactGives", { people: people(a.holders_gaining), ability: abilityName(a) }));
    }
    if (a.holders_losing > 0) {
      parts.push(t("impactRemoves", { people: people(a.holders_losing), ability: abilityName(a) }));
    }
  }
  const head = t("impactMoves", { moves: String(moves), to: String(to) });
  return `${head} ${parts.length === 0 ? t("impactNothing") : parts.join("; ")}.`;
}

/** The core meta-actions an admin delegation may cover, in the Kernel's order (L0-META-1). */
export const META: readonly {
  readonly label: Key;
  readonly reserved: boolean;
  readonly tier: string;
}[] = [
  { label: "metaAnchorCreate", reserved: true, tier: "ct3" },
  { label: "metaAnchorHandover", reserved: true, tier: "ct3" },
  { label: "metaAnchorAmend", reserved: true, tier: "ct3" },
  { label: "metaAnchorRetire", reserved: true, tier: "ct3" },
  { label: "metaPartyRegister", reserved: false, tier: "ct2" },
  { label: "metaPartyDepart", reserved: false, tier: "ct3" },
  { label: "metaInstanceCreate", reserved: false, tier: "ct2" },
  { label: "metaInstanceRekey", reserved: false, tier: "ct2" },
  { label: "metaInstanceTerminate", reserved: false, tier: "ct2" },
  { label: "metaInstanceRecover", reserved: false, tier: "ct3" },
  { label: "metaLimitsBind", reserved: false, tier: "ct2" },
  { label: "metaLimitsRebind", reserved: false, tier: "ct2" },
  { label: "metaLimitsRevoke", reserved: false, tier: "ct2" },
  { label: "metaGrantIssue", reserved: false, tier: "ct2" },
  { label: "metaGrantAmend", reserved: false, tier: "ct3" },
  { label: "metaGrantRevoke", reserved: false, tier: "ct2" },
  { label: "metaGrantRenounce", reserved: false, tier: "ct2" },
  { label: "metaAcceptanceEstablish", reserved: true, tier: "ct3" },
  { label: "metaAcceptanceAmend", reserved: true, tier: "ct3" },
  { label: "metaAcceptanceRevoke", reserved: true, tier: "ct2" },
  { label: "metaPolicySet", reserved: false, tier: "ct3" },
  { label: "metaPolicyRetire", reserved: false, tier: "ct3" },
  { label: "metaClaimIssue", reserved: false, tier: "ct2" },
  { label: "metaContribute", reserved: false, tier: "ct1" },
  { label: "metaConsumptionRelease", reserved: false, tier: "ct2" },
  { label: "metaAuthoritySetDefine", reserved: false, tier: "ct2" },
  { label: "metaProjectionIssue", reserved: false, tier: "ct1" },
];

/** Each core meta-action's plain label, by its canonical id (OP-151 m.19 (c)). */
export const META_BY_ACTION: Readonly<Record<string, Key>> = {
  anchor_create: "metaAnchorCreate",
  anchor_transfer: "metaAnchorHandover",
  anchor_amend: "metaAnchorAmend",
  anchor_retire: "metaAnchorRetire",
  party_register: "metaPartyRegister",
  party_depart: "metaPartyDepart",
  instance_create: "metaInstanceCreate",
  instance_rekey: "metaInstanceRekey",
  instance_terminate: "metaInstanceTerminate",
  instance_recover: "metaInstanceRecover",
  mandate_bind: "metaLimitsBind",
  mandate_rebind: "metaLimitsRebind",
  mandate_revoke: "metaLimitsRevoke",
  grant_issue: "metaGrantIssue",
  grant_amend: "metaGrantAmend",
  grant_revoke: "metaGrantRevoke",
  grant_renounce: "metaGrantRenounce",
  acceptance_establish: "metaAcceptanceEstablish",
  acceptance_amend: "metaAcceptanceAmend",
  acceptance_revoke: "metaAcceptanceRevoke",
  policy_set: "metaPolicySet",
  policy_retire: "metaPolicyRetire",
  claim_issue: "metaClaimIssue",
  contribute: "metaContribute",
  consumption_release: "metaConsumptionRelease",
  authority_set_define: "metaAuthoritySetDefine",
  projection_issue: "metaProjectionIssue",
};

/** The publisher's compatibility relation as words (§9.13.4); never "safe" or "equivalent" as fact. */
export function compatKey(relation: string): Key {
  if (relation === "narrowing" || relation === "narrows") return "compatNarrows";
  if (relation === "equivalent") return "compatEquivalent";
  if (relation === "widening" || relation === "widens") return "compatWidens";
  return "compatOther";
}
