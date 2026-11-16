// OP-159 m.47 (d), (g), TN-142: the first visit to an environment of the session's tenant. One signature
// registers this browser's key there (the administrator's `party_register` when the Party is new
// there, and `instance_create`); then the environment's screens open, with no new sign-in.

import { Button } from "@access/ui/components/button";
import { Card, CardContent, CardFooter, CardHeader } from "@access/ui/components/card";
import { Link } from "@tanstack/react-router";
import { type ReactElement, useState } from "react";

import { t } from "../i18n/index.js";
import { type Confirm, type Instance, NotSigned, registerIn } from "../lib/instance.js";
import { Failure, HINT, Page } from "../ui.js";

export function EnterEnvironment({
  environment,
  home,
  account,
  session,
  confirm,
  onRegistered,
}: {
  readonly environment: string;
  readonly home: string;
  readonly account: string;
  /** The session's own Instance, which must be registered first; `null` when it is not. */
  readonly session: string | null;
  readonly confirm: Confirm;
  readonly onRegistered: (i: Instance) => void;
}): ReactElement {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  const start = (own: string) => {
    setBusy(true);
    setFailed(false);
    registerIn(environment, account, own, confirm).then(
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
    <Page title={t("enterTitle", { environment })} intro={t("enterIntro", { home })}>
      <section aria-labelledby="enter-title" data-testid="enter-environment">
        <Card>
          <CardHeader>
            <h2 id="enter-title" className="text-lg font-semibold">
              {t("enterDeviceTitle")}
            </h2>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {session === null ? (
              <p>
                {t("enterNeedsHome", { home })}{" "}
                <Link
                  to="/$environment"
                  params={{ environment: home }}
                  className="text-primary underline underline-offset-2 hover:text-foreground"
                >
                  {t("enterGoHome", { home })}
                </Link>
              </p>
            ) : (
              <p className={HINT}>{t("enterDeviceText")}</p>
            )}
            {failed && <Failure>{t("enterFailed")}</Failure>}
          </CardContent>
          {session !== null && (
            <CardFooter>
              <Button
                disabled={busy}
                onClick={() => {
                  start(session);
                }}
              >
                {t("enterAction", { environment })}
              </Button>
            </CardFooter>
          )}
        </Card>
      </section>
    </Page>
  );
}
