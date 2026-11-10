// §8.5 S7, §8.17.7.6, §8.17.9.3, §8.17.9.7, §12.3.8, X20: organization authority admin. An
// organization reads with its roots and members, how each membership began (the membership
// source, never the sign-in source), the role's versioned delegation and any cooling, its domain
// claims, its ownership handovers and its connection drafts. Ownership is root standing over
// the organization, never billing; nothing here changes authority without a signed change.
import { useState, type ReactElement } from "react";

import { type Key, t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { at, type Ctx, Panel, Show, useLoad, useRun } from "./parts.js";
import { SsoEnforcement } from "./SsoEnforcement.js";

interface OrgSummary {
  readonly organization: string;
  readonly display_name: string;
  readonly hrd: boolean;
}

interface Member {
  readonly account_id: string;
  readonly owner: boolean;
  readonly membership_source: string;
  readonly role?: { readonly name: string; readonly version: number } | null;
  readonly role_grant?: string | null;
  readonly cooling_until?: string | null;
}

interface DomainClaim {
  readonly domain: string;
  readonly method: string;
  readonly verified_at?: string | null;
  readonly reverify_by?: string | null;
  readonly changed_at?: string | null;
  readonly contested_at?: string | null;
  readonly autojoin: boolean;
  readonly claimed: boolean;
}

interface Handover {
  readonly handover: string;
  readonly from: string;
  readonly to: string;
  readonly state: string;
  readonly effective_at: string;
  readonly dns_recovery: boolean;
}

interface Draft {
  readonly protocol: string;
  readonly issuer?: string | null;
  readonly client_id?: string | null;
  readonly entity_id?: string | null;
}

interface Organization extends OrgSummary {
  readonly roots: number;
  readonly members: readonly Member[];
  readonly domains: readonly DomainClaim[];
  readonly handovers: readonly Handover[];
  readonly connection_drafts: readonly Draft[];
}

const SOURCE: Readonly<Record<string, Key>> = {
  founder: "orgSourceFounder",
  invite: "orgSourceInvite",
  scim: "orgSourceScim",
  jit: "orgSourceJit",
  domain_autojoin: "orgSourceAutojoin",
};

const HANDOVER: Readonly<Record<string, Key>> = {
  proposed: "orgHandoverProposed",
  contributed: "orgHandoverContributed",
  cancelled: "orgHandoverCancelled",
  completed: "orgHandoverCompleted",
};

function roleText(m: Member): string {
  if (m.role === undefined || m.role === null) return t("orgNoRole");
  const state =
    m.role_grant === "issued"
      ? t("orgRoleIssued")
      : m.role_grant === "denied"
        ? t("orgRoleDenied")
        : t("orgRolePending");
  return `${m.role.name} v${String(m.role.version)} · ${state}`;
}

function domainState(d: DomainClaim): string {
  if (d.contested_at !== undefined && d.contested_at !== null) return t("orgDomainContested");
  if (d.changed_at !== undefined && d.changed_at !== null) return t("orgDomainChanged");
  if (d.claimed && d.verified_at !== undefined && d.verified_at !== null) {
    return t("orgDomainHeld", { until: at(d.reverify_by) });
  }
  return t("orgDomainPending");
}

function OrganizationView({ o }: { readonly o: Organization }): ReactElement {
  return (
    <article className="report" data-testid="organization">
      <h4>{o.display_name}</h4>
      <dl className="facts">
        <dt>{t("orgId")}</dt>
        <dd className="mono">{o.organization}</dd>
        <dt>{t("orgRoots")}</dt>
        <dd data-testid="org-roots">{t("orgRootsText", { n: String(o.roots) })}</dd>
        <dt>{t("orgHrd")}</dt>
        <dd>{o.hrd ? t("orgHrdOn") : t("orgHrdOff")}</dd>
      </dl>
      <p className="hint">{t("orgOwnershipNotBilling")}</p>
      <table data-testid="org-members">
        <caption>{t("orgMembers")}</caption>
        <thead>
          <tr>
            <th scope="col">{t("colAccount")}</th>
            <th scope="col">{t("orgMembershipSource")}</th>
            <th scope="col">{t("orgRole")}</th>
          </tr>
        </thead>
        <tbody>
          {o.members.map((m) => (
            <tr key={m.account_id}>
              <td className="mono">
                {m.account_id}
                {m.owner && ` · ${t("orgOwner")}`}
              </td>
              <td>{t(SOURCE[m.membership_source] ?? "orgSourceOther")}</td>
              <td>
                {roleText(m)}
                {m.cooling_until !== undefined &&
                  m.cooling_until !== null &&
                  ` · ${t("orgCooling", { until: at(m.cooling_until) })}`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="hint">{t("orgSourceApart")}</p>
      <h5>{t("orgDomains")}</h5>
      {o.domains.length === 0 ? (
        <p>{t("orgNoDomains")}</p>
      ) : (
        <ul data-testid="org-domains">
          {o.domains.map((d) => (
            <li key={d.domain}>
              <span className="mono">{d.domain}</span> · {domainState(d)}
              {d.autojoin && ` · ${t("orgAutojoinOn")}`}
            </li>
          ))}
        </ul>
      )}
      <h5>{t("orgHandovers")}</h5>
      {o.handovers.length === 0 ? (
        <p>{t("orgNoHandovers")}</p>
      ) : (
        <ul data-testid="org-handovers">
          {o.handovers.map((h) => (
            <li key={h.handover}>
              {t(HANDOVER[h.state] ?? "orgHandoverProposed")} ·{" "}
              {t("orgHandoverText", { from: h.from, to: h.to, at: at(h.effective_at) })}
              {h.dns_recovery && ` · ${t("orgDnsRecovery")}`}
            </li>
          ))}
        </ul>
      )}
      <p className="hint">{t("orgHandoverHow")}</p>
      <p className="hint" data-testid="org-dns-recovery">
        {t("orgNoDnsRecovery")}
      </p>
      <h5>{t("orgDrafts")}</h5>
      {o.connection_drafts.length === 0 ? (
        <p>{t("orgNoDrafts")}</p>
      ) : (
        <ul data-testid="org-drafts">
          {o.connection_drafts.map((d) => (
            <li key={`${d.issuer ?? ""}/${d.client_id ?? ""}/${d.entity_id ?? ""}`}>
              {d.protocol === "saml" ? (
                t("orgDraftSaml", { entity: d.entity_id ?? "" })
              ) : (
                <>
                  <span className="mono">{d.issuer}</span> · {d.client_id}
                </>
              )}{" "}
              · {t("orgDraftOnly")}
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

/** §8.5 S7, Ek B 3735, 3808, 3819, 3821: the realm's organizations, one opened at a time. */
export function Organizations({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const list = useLoad(() =>
    adminGet<{ readonly items: readonly OrgSummary[] }>(
      ctx.instance,
      `realms/${realm}/organizations`,
    ),
  );
  const [open, setOpen] = useState<string | undefined>(undefined);
  const [one, run] = useRun<Organization>();
  return (
    <>
      <p>{t("orgIntro")}</p>
      <Show l={list}>
        {(l) =>
          l.items.length === 0 ? (
            <p>{t("orgNone")}</p>
          ) : (
            <ul data-testid="org-list">
              {l.items.map((o) => (
                <li key={o.organization}>
                  <button
                    type="button"
                    aria-pressed={open === o.organization}
                    onClick={() => {
                      setOpen(o.organization);
                      run(() =>
                        adminGet<Organization>(
                          ctx.instance,
                          `realms/${realm}/organizations/${encodeURIComponent(o.organization)}`,
                        ),
                      );
                    }}
                  >
                    {o.display_name}
                  </button>
                </li>
              ))}
            </ul>
          )
        }
      </Show>
      {open !== undefined && (
        <Panel id="org-open" title={t("orgOpen")}>
          <Show l={one}>{(o) => <OrganizationView o={o} />}</Show>
          <SsoEnforcement key={open} ctx={ctx} org={open} />
        </Panel>
      )}
    </>
  );
}
