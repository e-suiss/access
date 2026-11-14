// §8.17.9.2, §8.17.10.2, §5.4, §16.5.1, X21: the developer-surface reports as text. None of them
// renders an action: there is no accept, move or stop button in any report (X21, §8.17.7.5).
import type { ReactElement } from "react";

import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@suiss/access-ui/components/ui/table";

import { t } from "../i18n/index.js";
import { type Ability, compatKey, impactSentence, relationKey } from "../lib/text.js";
import { Advisory, at, List } from "./parts.js";
import { BULLETS, FACTS, H4, HINT, MONO, REPORT } from "../ui.js";

export interface Publication {
  readonly type: "schema_publication";
  readonly fingerprint: string;
  readonly publisher: string;
  readonly namespace: string;
  readonly catalog_version: number;
  readonly standing: "accepted" | "pending_acceptance" | "unreferenced";
  readonly accepted_version?: number | null;
  readonly diff: {
    readonly added: readonly string[];
    readonly removed: readonly string[];
    readonly changed: readonly string[];
    readonly reserved_added: readonly string[];
    readonly reserved_removed: readonly string[];
  };
  readonly reserved?: readonly string[];
  readonly parameters?: readonly {
    readonly action: string;
    readonly parameter: string;
    readonly class: string;
    readonly affects?: string;
  }[];
  readonly compatibility?: { readonly from: number; readonly relation: string } | null;
  readonly existing_grants_unchanged: true;
  readonly new_actions?: readonly string[];
}

export function PublicationView({ p }: { readonly p: Publication }): ReactElement {
  const standing =
    p.standing === "accepted"
      ? t("standingAccepted")
      : p.standing === "pending_acceptance"
        ? t("standingPending")
        : t("standingUnreferenced");
  return (
    <article className={REPORT} aria-label={`${p.namespace} v${String(p.catalog_version)}`}>
      <h4 className={H4}>
        <span className={MONO}>{p.namespace}</span> ·{" "}
        {t("pubCatalog", { version: String(p.catalog_version) })}
      </h4>
      <Advisory />
      <p data-testid="standing">{standing}</p>
      {p.accepted_version !== undefined && p.accepted_version !== null && (
        <p>{t("pubAcceptedVersion", { version: String(p.accepted_version) })}</p>
      )}
      <dl className={FACTS}>
        <dt>{t("pubFingerprint")}</dt>
        <dd className={MONO} data-testid="fingerprint">
          {p.fingerprint}
        </dd>
        <dt>{t("pubPublisher")}</dt>
        <dd className={MONO}>{p.publisher}</dd>
        <dt>{t("diffAdded")}</dt>
        <dd>
          <List items={p.diff.added} />
        </dd>
        <dt>{t("diffRemoved")}</dt>
        <dd>
          <List items={p.diff.removed} />
        </dd>
        <dt>{t("diffChanged")}</dt>
        <dd>
          <List items={p.diff.changed} />
        </dd>
        <dt>{t("diffReservedAdded")}</dt>
        <dd>
          <List items={p.diff.reserved_added} />
        </dd>
        <dt>{t("diffReservedRemoved")}</dt>
        <dd>
          <List items={p.diff.reserved_removed} />
        </dd>
        <dt>{t("pubReserved")}</dt>
        <dd>
          <List items={p.reserved ?? []} />
        </dd>
        <dt>{t("pubParameters")}</dt>
        <dd>
          <ul className={BULLETS}>
            {(p.parameters ?? []).map((x) => (
              <li key={`${x.action}/${x.parameter}`}>
                <span className={MONO}>
                  {x.action}.{x.parameter}
                </span>
                {": "}
                {x.class === "authority-relevant"
                  ? t("paramRelevant", { affects: x.affects ?? "" })
                  : t("paramOpaque")}
              </li>
            ))}
          </ul>
        </dd>
      </dl>
      {p.compatibility !== undefined && p.compatibility !== null && (
        <p data-testid="compatibility">
          {t("pubCompat", {
            relation: t(compatKey(p.compatibility.relation)),
            from: String(p.compatibility.from),
          })}
        </p>
      )}
      <p data-testid="existing-unchanged">{t("pubExisting")}</p>
      {(p.new_actions ?? []).length > 0 && (
        <p data-testid="new-actions">
          {t("pubNewActions", {
            namespace: p.namespace,
            actions: (p.new_actions ?? []).join(", "),
          })}
        </p>
      )}
    </article>
  );
}

export interface ChangeImpact {
  readonly type: "change_impact";
  readonly role?: { readonly name: string; readonly from: number; readonly to: number };
  readonly relation: string;
  readonly moves?: readonly string[];
  readonly holders?: {
    readonly parties: number;
    readonly everyone: boolean;
    readonly upper_bound: boolean;
  };
  readonly abilities?: readonly Ability[];
  readonly expansion?: {
    readonly tier: string;
    readonly joint_root_quorum: number;
    readonly delay_s: number;
  } | null;
  readonly orphans?: {
    readonly empty_scopes: readonly string[];
    readonly unselecting: readonly string[];
  };
  readonly capped?: boolean;
}

export function ChangeImpactView({ c }: { readonly c: ChangeImpact }): ReactElement {
  const upper = c.holders?.upper_bound === true || c.capped === true;
  return (
    <article className={REPORT} data-testid="change-impact">
      <Advisory />
      {c.role !== undefined && (
        <p data-testid="impact-sentence">
          {impactSentence(c.moves?.length ?? 0, c.role.to, c.abilities ?? [], upper)}
        </p>
      )}
      <p>
        {c.role !== undefined && `${t("impactRelation", { from: String(c.role.from) })}: `}
        {t(relationKey(c.relation))}
      </p>
      {c.expansion !== undefined && c.expansion !== null && (
        <p data-testid="expansion">
          {t("impactExpansion", {
            tier: c.expansion.tier.toUpperCase(),
            quorum: String(c.expansion.joint_root_quorum),
            delay: String(c.expansion.delay_s),
          })}
        </p>
      )}
      <p>{t("impactExplicit")}</p>
      {(c.orphans?.empty_scopes.length ?? 0) > 0 && (
        <p>{t("impactOrphans", { n: String(c.orphans?.empty_scopes.length ?? 0) })}</p>
      )}
      {c.capped === true && <p>{t("impactCapped")}</p>}
    </article>
  );
}

export interface RevocationImpact {
  readonly type: "revocation_impact";
  readonly subtree: readonly string[];
  readonly exposed: readonly {
    readonly exercise: string;
    readonly holder: string;
    readonly class: string;
    readonly horizon_ms: number;
    readonly window_ms: number;
    readonly pep?: string;
    readonly applied_at?: number | null;
  }[];
  readonly max_exposure_ms?: number;
  readonly index_lag?: number;
  readonly orphan_tuples: number;
  readonly acknowledged?: readonly {
    readonly pep: string;
    readonly applied_at: number;
    readonly basis: number;
  }[];
  readonly aftermath: {
    readonly grants_ending: number;
    readonly projections_open: number;
    readonly honoured_until_ms: number | null;
    readonly running_copies: number;
    readonly confirmed_applied?: number;
  };
}

/**
 * §9.12.3, E30, Ek B 3883: where a revocation took effect is each decision point's own report;
 * one that has not reported is unknown, never "not applied", and delivery is not authority.
 */
export function Acknowledgements({ r }: { readonly r: RevocationImpact }): ReactElement {
  const acks = r.acknowledged ?? [];
  return (
    <section
      aria-label={t("revocationAcks")}
      data-testid="acknowledged"
      className="flex flex-col gap-2"
    >
      <h5 className={H4}>{t("revocationAcks")}</h5>
      <p className={HINT}>{t("revocationAcksIntro")}</p>
      {acks.length === 0 ? (
        <p>{t("revocationAcksNone")}</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead scope="col">{t("colPep")}</TableHead>
              <TableHead scope="col">{t("colAppliedAt")}</TableHead>
              <TableHead scope="col">{t("colBasis")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {acks.map((a) => (
              <TableRow key={a.pep}>
                <TableCell className={`${MONO} whitespace-normal`}>{a.pep}</TableCell>
                <TableCell className="whitespace-normal">{at(a.applied_at)}</TableCell>
                <TableCell className={`${MONO} whitespace-normal`}>{a.basis}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  );
}

/** §8.17.7.3, §8.17.7.4, §8.10: the impact preview and aftermath lines, each from its owner. */
export function Aftermath({ r }: { readonly r: RevocationImpact }): ReactElement {
  const horizon = r.exposed.reduce((m, e) => Math.max(m, e.horizon_ms), 0);
  const a = r.aftermath;
  return (
    <ul className={BULLETS} data-testid="aftermath">
      <li>{t("aftermathAuthority")}</li>
      <li>{horizon > 0 ? t("aftermathWindow", { until: at(horizon) }) : t("aftermathNoWindow")}</li>
      {a.grants_ending > 0 && <li>{t("aftermathEnding", { n: String(a.grants_ending) })}</li>}
      {a.projections_open > 0 && (
        <li>
          {t("aftermathOffline", {
            n: String(a.projections_open),
            until: at(a.honoured_until_ms),
          })}
        </li>
      )}
      {a.running_copies > 0 && <li>{t("aftermathCopies", { n: String(a.running_copies) })}</li>}
      {(a.confirmed_applied ?? 0) > 0 && (
        <li>{t("aftermathConfirmed", { n: String(a.confirmed_applied ?? 0) })}</li>
      )}
      <li>{t("aftermathRuntime")}</li>
      <li>{t("aftermathHistory")}</li>
    </ul>
  );
}

export function RevocationView({ r }: { readonly r: RevocationImpact }): ReactElement {
  return (
    <article className={REPORT} data-testid="revocation-impact">
      <h4 className={H4}>{t("revocationRevoke")}</h4>
      <Advisory />
      <Aftermath r={r} />
      <p>{t("revocationSubtree", { n: String(r.subtree.length) })}</p>
      {r.exposed.length > 0 && (
        <Table>
          <TableCaption className="mt-0 mb-2 caption-top text-start">
            {t("revocationExposed")}
          </TableCaption>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead scope="col">{t("unknownPosition")}</TableHead>
              <TableHead scope="col">{t("colHolder")}</TableHead>
              <TableHead scope="col">{t("unknownUntil")}</TableHead>
              <TableHead scope="col">{t("colPep")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {r.exposed.map((e) => (
              <TableRow key={e.exercise}>
                <TableCell className={`${MONO} whitespace-normal`}>{e.exercise}</TableCell>
                <TableCell className={`${MONO} whitespace-normal`}>{e.holder}</TableCell>
                <TableCell className="whitespace-normal">{at(e.horizon_ms)}</TableCell>
                <TableCell className="whitespace-normal">
                  {e.applied_at === undefined || e.applied_at === null
                    ? t("exposedUnknown")
                    : t("exposedApplied", { at: at(e.applied_at) })}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {r.max_exposure_ms !== undefined && (
        <p>{t("revocationMax", { s: String(Math.ceil(r.max_exposure_ms / 1000)) })}</p>
      )}
      {(r.index_lag ?? 0) > 0 && <p>{t("revocationLag", { n: String(r.index_lag ?? 0) })}</p>}
      {r.orphan_tuples > 0 && <p>{t("revocationOrphans", { n: String(r.orphan_tuples) })}</p>}
      <Acknowledgements r={r} />
    </article>
  );
}

export interface CompromiseImpact {
  readonly type: "compromise_impact";
  readonly instance?: string | null;
  readonly exercises: readonly {
    readonly pos: number;
    readonly intent: string;
    readonly outcome?: string | null;
  }[];
  readonly grants: readonly string[];
  readonly contributions: readonly string[];
  readonly projections: readonly string[];
  readonly claims: readonly string[];
  readonly capped?: boolean;
}

/** EI-22, §8.10: a missing report is "Result unknown", never "Failed". */
export function CompromiseView({ c }: { readonly c: CompromiseImpact }): ReactElement {
  return (
    <article className={REPORT} data-testid="compromise-impact">
      <Advisory />
      <Table>
        <TableCaption className="mt-0 mb-2 caption-top text-start">
          {t("unknownExercises")}
        </TableCaption>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead scope="col">{t("unknownPosition")}</TableHead>
            <TableHead scope="col">{t("unknownOutcome")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {c.exercises.map((e) => (
            <TableRow key={e.pos}>
              <TableCell className={`${MONO} whitespace-normal`}>{e.pos}</TableCell>
              <TableCell className="whitespace-normal">
                {e.outcome === undefined || e.outcome === null || e.outcome === "unknown"
                  ? t("outcomeUnknown")
                  : e.outcome}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <p>{t("unknownGrants", { n: String(c.grants.length) })}</p>
      <p>{t("unknownContributions", { n: String(c.contributions.length) })}</p>
      <p>{t("unknownProjections", { n: String(c.projections.length) })}</p>
      <p>{t("unknownClaims", { n: String(c.claims.length) })}</p>
      {c.capped === true && <p>{t("impactCapped")}</p>}
    </article>
  );
}
