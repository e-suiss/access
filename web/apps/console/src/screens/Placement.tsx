// TI-17, CMP-26, OP-30, OP-158 m.3 (o): Settings ▸ Placement. The cell this environment, its governing
// domain and its tenant are served from, the cell's region and the environment's residency, and any
// rehome waiting for its second governing domain. Placement only routes requests.

import { Card, CardContent } from "@access/ui/components/card";
import type { ReactElement } from "react";
import * as v from "valibot";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { BULLETS, HINT, MONO, ROWS } from "../ui.js";
import { type Ctx, readKey, Show, useLoad } from "./parts.js";

// OP-159 m.46 (f)
const Placed = v.looseObject({ cell: v.string(), dedicated: v.boolean(), version: v.number() });

type Placed = v.InferOutput<typeof Placed>;

const PendingEnd = v.looseObject({
  side: v.picklist(["from", "to"]),
  to: v.string(),
  position: v.string(),
});

const PlacementView = v.looseObject({
  cell: v.nullable(v.string()),
  region: v.nullable(v.string()),
  dedicated_cell: v.boolean(),
  tenant: v.nullable(Placed),
  environment: v.nullable(Placed),
  domain: v.nullable(Placed),
  governing_domain: v.string(),
  residency: v.nullable(v.looseObject({ region: v.string(), class: v.string() })),
  pending_rehome: v.array(PendingEnd),
});

type PlacementView = v.InferOutput<typeof PlacementView>;

/** The cell a subject is served from: its own placement, else the cell that holds it. */
const cellOf = (v: PlacementView, p: Placed | null): string => p?.cell ?? v.cell ?? t("none");

/** The placement screen. */
export function Placement({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const environment = encodeURIComponent(ctx.session.environment);
  const view = useLoad(readKey(ctx, `envs/${environment}/placement`), () =>
    adminGet(ctx.instance, `envs/${environment}/placement`, PlacementView),
  );
  return (
    <div data-testid="placement" className="flex flex-col gap-4">
      <p className="text-muted-foreground">{t("placementIntro")}</p>
      <Show l={view}>
        {(v) => (
          <Card>
            <CardContent className="flex flex-col gap-4">
              <dl className={ROWS} data-testid="placement-cells">
                <div>
                  <dt>{t("placementCell")}</dt>
                  <dd className={MONO} data-testid="placement-environment-cell">
                    {cellOf(v, v.environment)}
                  </dd>
                </div>
                <div>
                  <dt>{t("domainId")}</dt>
                  <dd className={MONO} data-testid="placement-domain-cell">
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
                  {t("placementResidency", {
                    region: v.residency.region,
                    class: v.residency.class,
                  })}
                </p>
              )}
              <h3 className="text-base font-semibold">{t("placementRehome")}</h3>
              <p className={HINT}>{t("placementRehomeBoth")}</p>
              {v.pending_rehome.length > 0 && (
                <ul data-testid="placement-pending" className={BULLETS}>
                  {v.pending_rehome.map((e) => (
                    <li key={`${e.side}-${e.position}`} className={MONO}>
                      {e.side} → {e.to}
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        )}
      </Show>
    </div>
  );
}
