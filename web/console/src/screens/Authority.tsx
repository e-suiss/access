// §8.17.4.1: the Authority hub; its views come with the authority read screens. Here the
// browser's device key is registered (OP-151 m.3 (e)), without which nothing is signed.
import { useState, type ReactElement } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent, CardFooter, CardHeader } from "@suiss/access-ui/components/ui/card";

import { t } from "../i18n/index.js";
import { type Confirm, type Instance, NotSigned, register } from "../lib/instance.js";
import type { SessionInfo } from "../lib/api.js";
import { Failure, Page } from "../ui.js";

export function Authority({
  session,
  instance,
  confirm,
  onRegistered,
}: {
  readonly session: SessionInfo;
  readonly instance: Instance | undefined;
  readonly confirm: Confirm;
  readonly onRegistered: (i: Instance) => void;
}): ReactElement {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const canRegister = instance === undefined && session.instance === null;

  const start = () => {
    setBusy(true);
    setFailed(false);
    register(session.realm, session.account, confirm).then(
      (i) => {
        setBusy(false);
        onRegistered(i);
      },
      (e: unknown) => {
        setBusy(false);
        if (!(e instanceof NotSigned)) setFailed(true);
      },
    );
  };

  return (
    <Page title={t("authorityTitle")} intro={t("authorityIntro")}>
      <section aria-labelledby="device-title">
        <Card>
          <CardHeader>
            <h2 id="device-title" className="text-lg font-semibold">
              {t("deviceTitle")}
            </h2>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <p data-testid="device-state" className="flex items-center gap-2">
              <span
                aria-hidden
                className={`size-2 shrink-0 rounded-full ${instance === undefined ? "bg-muted-foreground" : "bg-primary"}`}
              />
              {instance === undefined ? t("deviceNone") : t("deviceReady")}
            </p>
            {failed && <Failure>{t("unavailable")}</Failure>}
          </CardContent>
          {canRegister && (
            <CardFooter>
              <Button isDisabled={busy} onPress={start}>
                {t("deviceRegister")}
              </Button>
            </CardFooter>
          )}
        </Card>
      </section>
    </Page>
  );
}
