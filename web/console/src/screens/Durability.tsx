// HL-40, SEC23, OP-29, OP-158 m.3 (n), (p): Settings ▸ Durability. Whether the cell is
// replicated or a single node, the realm's DR class and what a disaster can lose, and the
// witnesses and replicas its governing domain declares. Without an independent witness and a
// replica, revocations are never shown as confirmed.
import type { ReactElement } from "react";

import { t } from "../i18n/index.js";
import { adminGet } from "../lib/admin.js";
import { type Ctx, Show, useLoad } from "./parts.js";

interface Declared {
  readonly name: string;
  readonly operator: string;
  readonly independent: boolean;
}

interface DurabilityView {
  readonly durability: "replicated" | "single-node" | null;
  readonly class: string | null;
  readonly region: string | null;
  readonly dr_profile: { readonly rpo_s: number } | null;
  readonly rpo_s: number | null;
  readonly witnesses?: readonly Declared[];
  readonly replicas?: readonly Declared[];
  readonly acknowledges?: boolean;
}

function Parties({
  items,
  testid,
}: {
  readonly items: readonly Declared[];
  readonly testid: string;
}): ReactElement {
  return items.length === 0 ? (
    <p>{t("none")}</p>
  ) : (
    <ul data-testid={testid}>
      {items.map((w) => (
        <li key={w.name}>
          <span className="mono">{w.name}</span> · {w.operator} ·{" "}
          {w.independent ? t("durabilityWitnessIndependent") : t("durabilityWitnessNotIndependent")}
        </li>
      ))}
    </ul>
  );
}

/** The durability screen. */
export function Durability({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const view = useLoad(() => adminGet<DurabilityView>(ctx.instance, `realms/${realm}/durability`));
  return (
    <div data-testid="durability">
      <p>{t("durabilityIntro")}</p>
      <Show l={view}>
        {(v) => (
          <>
            <p data-testid="durability-profile" data-durability={v.durability ?? "unknown"}>
              {v.durability === "single-node"
                ? t("durabilitySingleNode")
                : t("durabilityReplicated")}
            </p>
            <p data-testid="durability-dr">
              {v.dr_profile === null
                ? t("durabilityDrSync")
                : t("durabilityDr", {
                    class: v.class ?? "regional",
                    rpo: `${String(v.dr_profile.rpo_s)} s`,
                  })}
            </p>
            <h3>{t("durabilityWitnesses")}</h3>
            <Parties items={v.witnesses ?? []} testid="durability-witnesses" />
            <h3>{t("durabilityReplicas")}</h3>
            <Parties items={v.replicas ?? []} testid="durability-replicas" />
            {v.acknowledges !== true && (
              <p role="status" data-testid="durability-unconfirmed">
                {t("durabilityNoWitness")}
              </p>
            )}
          </>
        )}
      </Show>
    </div>
  );
}
