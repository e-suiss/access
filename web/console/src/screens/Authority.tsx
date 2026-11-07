// §8.17.4.1: the Authority hub; its views come with the authority read screens. Here the
// browser's device key is registered (OP-151 m.3 (e)), without which nothing is signed.
import { useState, type ReactElement } from "react";

import { t } from "../i18n/index.js";
import { type Confirm, type Instance, NotSigned, register } from "../lib/instance.js";
import type { SessionInfo } from "../lib/api.js";

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
    <main id="main" tabIndex={-1}>
      <h1>{t("authorityTitle")}</h1>
      <p>{t("authorityIntro")}</p>
      <section aria-labelledby="device-title" className="panel">
        <h2 id="device-title">{t("deviceTitle")}</h2>
        <p data-testid="device-state">
          {instance === undefined ? t("deviceNone") : t("deviceReady")}
        </p>
        {failed && <p role="alert">{t("unavailable")}</p>}
        {canRegister && (
          <button type="button" className="primary" disabled={busy} onClick={start}>
            {t("deviceRegister")}
          </button>
        )}
      </section>
    </main>
  );
}
