// OP-149 m.6, OP-151 m.3 (e), OP-153 m.3 (w): the Authority hub needs this browser's device
// Instance. Setting it up asks for a fresh, stepped-up sign-in; the page says so plainly and
// never offers to skip it.
import { Alert } from "@suiss/access-ui/components/ui/alert";
import { Button } from "@suiss/access-ui/components/ui/button";
import { useState, type ReactElement } from "react";

import { Problem, type SessionInfo } from "../lib/api.js";
import { t } from "../lib/i18n.js";
import { Actions, Panel } from "../lib/ui.js";
import { type Confirm, type Instance, NotSigned, register } from "../lib/instance.js";

export function DeviceSetup({
  session,
  confirm,
  onReady,
}: {
  readonly session: SessionInfo;
  readonly confirm: Confirm;
  readonly onReady: (i: Instance) => void;
}): ReactElement {
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const supported = typeof indexedDB !== "undefined" && isSecureContext;
  return (
    <Panel aria-label={t("device.title")} data-testid="device-setup" title={t("device.title")}>
      <p>{t("device.explain")}</p>
      {!supported && <Alert variant="destructive">{t("device.unsupported")}</Alert>}
      {message !== null && (
        <Alert variant="destructive" data-testid="device-message">
          {message}
        </Alert>
      )}
      <Actions>
        <Button
          isDisabled={!supported || busy}
          onPress={() => {
            setBusy(true);
            setMessage(null);
            register(session.realm, session.account, session.pep, confirm)
              .then(onReady)
              .catch((e: unknown) => {
                if (e instanceof NotSigned) return;
                if (e instanceof Problem && e.code === "step-up-required") {
                  setMessage(t("device.step_up"));
                  return;
                }
                setMessage(t("shell.unavailable"));
              })
              .finally(() => {
                setBusy(false);
              });
          }}
        >
          {t("action.set_up_device")}
        </Button>
      </Actions>
    </Panel>
  );
}
