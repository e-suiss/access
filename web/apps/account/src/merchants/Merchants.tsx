// OP-156 m.3 (v), S2 "Merchants that can charge you" (§8.11, §8.17.5.11, §8.17.7.2), XI-14,
// X30, E26, XI-3: the merchants holding a pay Grant from this person, read with this browser's
// device key. Stop charges is the person's own grant.revoke, shown done only once recorded;
// Pay's agreements are Pay's to show and cancel, apart from this.

import { payment } from "@access/ui";
import { Alert } from "@access/ui/components/alert";
import { Card, CardContent } from "@access/ui/components/card";
import { pay } from "@esuiss/access";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";

import { revoke, search } from "../lib/adp.js";
import { catalogue, locale, t } from "../lib/i18n.js";
import type { Confirm, Instance } from "../lib/instance.js";
import { Loading } from "../lib/ui.js";

export function MerchantsPage({
  instance,
  confirm,
}: {
  readonly instance: Instance;
  readonly confirm: Confirm;
}): ReactElement {
  const queries = useQueryClient();
  const key = ["merchants", instance.party] as const;
  const { data: merchants, error } = useQuery({
    queryKey: key,
    queryFn: async () =>
      pay.merchantsOf((await search(instance, "inventory", { party: instance.party })).results),
  });
  const stop = useMutation({
    mutationFn: (grant: string) => revoke(instance, confirm, grant),
    onSuccess: (r) => {
      if (r.shown === "outcome.confirmed") void queries.invalidateQueries({ queryKey: key });
    },
  });
  const stopping = stop.data;
  if (error !== null) {
    return (
      <Alert variant="destructive" data-testid="merchants-unknown">
        {t("domain.unreachable")}
      </Alert>
    );
  }
  if (merchants === undefined) return <Loading status />;
  const period = (p: "transaction" | "day" | "month") => t(`period.${p}`);
  return (
    <Card data-testid="merchants">
      <CardContent className="flex flex-col gap-4">
        <payment.Merchants
          merchants={merchants.map((m) => ({
            grant: m.grant,
            name: m.merchant,
            agent: m.agent,
            limits: payment.limitRows(m.budget, [], locale, period),
          }))}
          catalogue={catalogue}
          onStop={(grant) => {
            stop.mutate(grant);
          }}
        />
        {stopping !== undefined && (
          <p role="status" data-testid="outcome" className="font-semibold">
            {t(stopping.shown)}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
