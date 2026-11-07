// §8.17.8, E-1…E-7, OP-151 m.8 (d), (e): a decision as the viewer may see it. Only the members
// listed here are rendered; anything else an answer carries (policy content, thresholds,
// statement bodies) is never shown (§8.17.8.5). Holders two or more steps below the viewer come
// as pseudonyms and stay pseudonyms.
import type { ReactElement } from "react";

import { t } from "../i18n/index.js";
import type { Explained } from "../lib/adp.js";
import { blockerText } from "../lib/text.js";
import { Advisory, at } from "./parts.js";

interface Named {
  readonly id?: string;
  readonly pseudonym?: string;
}

interface Hop {
  readonly hop: number;
  readonly grant: Named;
  readonly holder?: Named;
}

interface AdminReason {
  readonly category: string;
  readonly code: string;
  readonly subcode?: string;
}

interface ReasonAdmin {
  readonly basis_ref?: {
    readonly domain?: string;
    readonly position_q_minus_1?: number;
    readonly version_vector_digest?: string;
  };
  readonly state_basis?: {
    readonly evaluated_at?: number;
    readonly reads?: readonly { readonly key: string; readonly version: number }[];
  };
  readonly reasons?: readonly AdminReason[];
  readonly cited?: readonly string[];
}

function named(n: Named): string {
  if (n.pseudonym !== undefined) return t("explainPseudonym", { ref: n.pseudonym });
  return t("explainHolder", { ref: n.id ?? "" });
}

function arr(v: unknown): readonly unknown[] {
  return Array.isArray(v) ? (v as unknown[]) : [];
}

export function Explanation({
  answer,
  record,
}: {
  readonly answer: Explained;
  readonly record?: number;
}): ReactElement {
  const c = answer.context ?? {};
  const blockers = arr(c["blockers"])
    .map(blockerText)
    .filter((b): b is { what: string; fix: string } => b !== undefined);
  const lineage = arr(c["lineage"]) as readonly Hop[];
  const selection = c["selection"] !== undefined;
  const admin = c["reason_admin"] as ReasonAdmin | undefined;
  return (
    <div className="explanation" data-testid="explanation">
      <h4>
        {record === undefined
          ? t("explainNow")
          : t("explainRecorded", { position: String(record) })}
      </h4>
      {c["advisory"] === true && <Advisory />}
      <p data-testid="decision">
        {answer.decision === true ? t("explainAllowed") : t("explainNotAllowed")}
      </p>
      {blockers.length > 0 && (
        <dl>
          {blockers.map((b) => (
            <div key={b.what}>
              <dt>{b.what}</dt>
              <dd>
                {t("explainNeeds")}: {b.fix}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {lineage.length > 0 && (
        <>
          <h5>{t("explainPath")}</h5>
          <ol data-testid="lineage">
            {lineage.map((h) => (
              <li key={h.hop}>
                {t("explainHop", { hop: String(h.hop) })}:{" "}
                <span className="mono">{named(h.grant)}</span>
                {h.holder !== undefined && (
                  <>
                    {" → "}
                    <span className="mono">{named(h.holder)}</span>
                  </>
                )}
              </li>
            ))}
          </ol>
        </>
      )}
      {selection && (
        <>
          <h5>{t("explainSelection")}</h5>
          <p data-testid="selection">{t("explainSelectionText")}</p>
        </>
      )}
      {admin !== undefined && (
        <section aria-label={t("explainBasis")} data-testid="reason-admin">
          <h5>{t("explainBasis")}</h5>
          <dl>
            {admin.basis_ref?.position_q_minus_1 !== undefined && (
              <>
                <dt>
                  {t("explainBasisPosition", { n: String(admin.basis_ref.position_q_minus_1) })}
                </dt>
                <dd className="mono">{admin.basis_ref.domain}</dd>
              </>
            )}
            {admin.basis_ref?.version_vector_digest !== undefined && (
              <>
                <dt>{t("explainBasisDigest")}</dt>
                <dd className="mono">{admin.basis_ref.version_vector_digest}</dd>
              </>
            )}
            {admin.state_basis?.evaluated_at !== undefined && (
              <>
                <dt>{t("explainEvaluatedAt", { at: at(admin.state_basis.evaluated_at) })}</dt>
                <dd>
                  {t("explainReads")}
                  <ul>
                    {(
                      arr(admin.state_basis.reads) as readonly { key: string; version: number }[]
                    ).map((r) => (
                      <li key={r.key} className="mono">
                        {r.key} v{r.version}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            {(arr(admin.reasons) as readonly AdminReason[]).length > 0 && (
              <>
                <dt>{t("explainAdminReasons")}</dt>
                <dd>
                  <ul>
                    {(arr(admin.reasons) as readonly AdminReason[]).map((r) => (
                      <li key={`${r.category}/${r.code}/${r.subcode ?? ""}`} className="mono">
                        {r.category} · {r.code}
                        {r.subcode === undefined ? "" : ` · ${r.subcode}`}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
            {(arr(admin.cited) as readonly string[]).length > 0 && (
              <>
                <dt>{t("explainCited")}</dt>
                <dd>
                  <ul>
                    {(arr(admin.cited) as readonly string[]).map((x) => (
                      <li key={x} className="mono">
                        {x}
                      </li>
                    ))}
                  </ul>
                </dd>
              </>
            )}
          </dl>
        </section>
      )}
    </div>
  );
}
