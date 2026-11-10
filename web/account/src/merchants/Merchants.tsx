// OP-156 m.3 (v), S2 "Merchants that can charge you" (§8.11, §8.17.5.11, §8.17.7.2), XI-14,
// X30, E26, XI-3: the merchants holding a pay Grant from this person, read with this browser's
// device key. Stop charges is the person's own grant.revoke, shown done only once recorded;
// Pay's agreements are Pay's to show and cancel, apart from this.
import { pay } from "@esuiss/access";
import { payment } from "@suiss/access-react";
import { useCallback, useEffect, useState, type ReactElement } from "react";

import { revoke, search, type Revoking } from "../lib/adp.js";
import { catalogue, locale, t } from "../lib/i18n.js";
import type { Confirm, Instance } from "../lib/instance.js";

type Loaded =
  | { readonly kind: "loading" }
  | { readonly kind: "unknown" }
  | { readonly kind: "ready"; readonly merchants: readonly pay.MerchantHolding[] };

export function MerchantsPage({
  instance,
  confirm,
}: {
  readonly instance: Instance;
  readonly confirm: Confirm;
}): ReactElement {
  const [loaded, setLoaded] = useState<Loaded>({ kind: "loading" });
  const [stopping, setStopping] = useState<Revoking | null>(null);
  const load = useCallback(() => {
    search(instance, "inventory", { party: instance.party })
      .then((a) => {
        setLoaded({ kind: "ready", merchants: pay.merchantsOf(a.results) });
      })
      .catch(() => {
        setLoaded({ kind: "unknown" });
      });
  }, [instance]);
  useEffect(load, [load]);
  if (loaded.kind === "loading") return <p role="status">{t("shell.loading")}</p>;
  if (loaded.kind === "unknown") {
    return (
      <p role="alert" data-testid="merchants-unknown">
        {t("domain.unreachable")}
      </p>
    );
  }
  const period = (p: "transaction" | "day" | "month") => t(`period.${p}`);
  return (
    <div data-testid="merchants">
      <payment.Merchants
        merchants={loaded.merchants.map((m) => ({
          grant: m.grant,
          name: m.merchant,
          agent: m.agent,
          limits: payment.limitRows(m.budget, [], locale, period),
        }))}
        catalogue={catalogue}
        onStop={(grant) => {
          revoke(instance, confirm, grant)
            .then((r) => {
              setStopping(r);
              if (r.shown === "outcome.confirmed") load();
            })
            .catch(() => {
              setStopping(null);
            });
        }}
      />
      {stopping !== null && (
        <p role="status" data-testid="outcome">
          {t(stopping.shown)}
        </p>
      )}
    </div>
  );
}
