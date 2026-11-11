// TI-17, CMP-26, OP-30, OP-158 m.3 (o): Settings ▸ Placement. The cell this realm, its governing
// domain and its tenant are served from, the cell's region and the realm's residency, and any
// rehome waiting for its second governing domain. Placement only routes requests.
import type { ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { type Ctx, Show, useLoad } from "./parts.js";

interface Placed {
  readonly cell: string;
  readonly dedicated: boolean;
  readonly version: number;
}

interface PendingEnd {
  readonly side: "from" | "to";
  readonly to: string;
  readonly position: string;
}

interface PlacementView {
  readonly cell: string | null;
  readonly region: string | null;
  readonly dedicated_cell: boolean;
  readonly tenant: Placed | null;
  readonly realm: Placed | null;
  readonly domain: Placed | null;
  readonly governing_domain: string;
  readonly residency: { readonly region: string; readonly class: string } | null;
  readonly pending_rehome: readonly PendingEnd[];
}

/** The cell a subject is served from: its own placement, else the cell that holds it. */
const cellOf = (v: PlacementView, p: Placed | null): string => p?.cell ?? v.cell ?? t("none");

/** The placement screen. */
export function Placement({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const view = useLoad(() => adminGet<PlacementView>(ctx.instance, `realms/${realm}/placement`));
  return (
    <div data-testid="placement">
      <p>{t("placementIntro")}</p>
      <Show l={view}>
        {(v) => (
          <>
            <dl className="facts" data-testid="placement-cells">
              <div>
                <dt>{t("placementCell")}</dt>
                <dd className="mono" data-testid="placement-realm-cell">
                  {cellOf(v, v.realm)}
                </dd>
              </div>
              <div>
                <dt>{t("domainId")}</dt>
                <dd className="mono" data-testid="placement-domain-cell">
                  {v.governing_domain} · {cellOf(v, v.domain)}
                </dd>
              </div>
              {(v.dedicated_cell || v.tenant?.dedicated === true) && (
                <div>
                  <dt>{t("placementDedicated")}</dt>
                  <dd data-testid="placement-dedicated">{cellOf(v, v.tenant)}</dd>
                </div>
              )}
            </dl>
            {v.residency !== null && (
              <p data-testid="placement-residency">
                {t("placementResidency", { region: v.residency.region, class: v.residency.class })}
              </p>
            )}
            <h3>{t("placementRehome")}</h3>
            <p>{t("placementRehomeBoth")}</p>
            {v.pending_rehome.length > 0 && (
              <ul data-testid="placement-pending">
                {v.pending_rehome.map((e) => (
                  <li key={`${e.side}-${e.position}`} className="mono">
                    {e.side} → {e.to}
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </Show>
    </div>
  );
}
