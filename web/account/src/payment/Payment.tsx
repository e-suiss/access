// OP-156 m.3 (v), §8.17.5.11, R8, X8, X11, XI-3: the hosted one-time payment page. It shows
// "Pay 300 TRY to M, once" from the Kernel's decoding of the request's bytes, and the outcome
// only as Access recorded it.
import type { pay } from "@esuiss/access";
import { honesty, payment } from "@suiss/access-react";
import { Alert } from "@suiss/access-ui/components/ui/alert";
import { Button } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent } from "@suiss/access-ui/components/ui/card";
import { useEffect, useState, type ReactElement } from "react";

import { catalogue, locale, t } from "../lib/i18n.js";
import type { Confirm, Instance } from "../lib/instance.js";
import { Actions, Loading, Panel } from "../lib/ui.js";
import { decode, payOnce, type Paying, requestOf } from "./pay.js";

export function OneTimePaymentPage({
  instance,
  confirm,
}: {
  readonly instance: Instance;
  readonly confirm: Confirm;
}): ReactElement {
  const [request] = useState(() => requestOf(location.hash));
  const [decoded, setDecoded] = useState<pay.OneTime | pay.NotOneTime | null>(null);
  const [paid, setPaid] = useState<{ p: Paying; next: honesty.Next } | null>(null);
  const setPaying = (p: Paying) => {
    setPaid({ p, next: honesty.next(p.attempt, Date.now()) });
  };
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (request === undefined) return;
    void decode(request).then(setDecoded);
  }, [request]);
  if (request === undefined) {
    return <Alert variant="destructive">{t("shell.unavailable")}</Alert>;
  }
  if (decoded === null) return <Loading status />;
  if (paid !== null) {
    const { p: paying, next } = paid;
    return (
      <Panel
        aria-label={t("payment.one_time_title")}
        data-testid="paid"
        title={t("payment.one_time_title")}
      >
        <p role="status" data-testid="outcome" className="font-semibold">
          {t(paying.shown)}
        </p>
        {next === "retry_same_nonce" && (
          <Actions>
            <Button
              onPress={() => {
                void paying.retry().then(setPaying);
              }}
            >
              {t("action.read_again")}
            </Button>
          </Actions>
        )}
      </Panel>
    );
  }
  return (
    <Card data-testid="payment">
      <CardContent className="flex flex-col gap-4">
        <payment.OneTimePayment
          payment={decoded}
          merchant={request.merchant}
          locale={locale}
          busy={busy}
          catalogue={catalogue}
          onPay={() => {
            setBusy(true);
            payOnce(instance, confirm, request)
              .then(setPaying)
              .catch(() => {
                setFailed(true);
              })
              .finally(() => {
                setBusy(false);
              });
          }}
          onCancel={() => {
            history.back();
          }}
        />
        {failed && <Alert variant="destructive">{t("outcome.not_recorded")}</Alert>}
      </CardContent>
    </Card>
  );
}
