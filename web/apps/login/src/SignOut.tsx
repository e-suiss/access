// TN-152, OIDC RP-Initiated Logout §2, §5: the pages the end-session endpoint sends a browser to.
// A sign-out the client did not tie to this browser's session is confirmed first; a finished one
// says so and offers a new sign-in. No page names an app or leads back to one.

import { Button } from "@access/ui/components/button";
import { useEffect, useRef, useState } from "react";

import { ENVIRONMENT, LOGIN } from "./base.js";
import { Empty, postJson } from "./http.js";
import { t } from "./i18n.js";
import { otherLink, Panel, primary, problem, quiet, stack, Title } from "./Layout.js";

/** `/login/sign-out`: the confirmation. */
export function SignOut() {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    title.current?.focus();
  }, []);
  const confirm = async () => {
    setBusy(true);
    const a = await postJson("/v1/sessions/current/sign-out", {}, Empty);
    if (a.ok || a.status === 401) {
      window.location.assign(`${LOGIN}/signed-out`);
      return;
    }
    setBusy(false);
    setFailed(true);
  };
  return (
    <Panel aria-busy={busy}>
      <section aria-labelledby="sign-out-heading" data-kind="sign_out" className={stack}>
        <Title id="sign-out-heading" ref={title}>
          {t("signout.confirm_title")}
        </Title>
        {failed && (
          <p role="alert" className={problem}>
            {t("login.unavailable")}
          </p>
        )}
        <Button {...primary} disabled={busy} onClick={() => void confirm()}>
          {t("signout.confirm")}
        </Button>
        <Button
          {...quiet}
          disabled={busy}
          onClick={() => window.location.assign(`${ENVIRONMENT}/account`)}
        >
          {t("signout.stay")}
        </Button>
      </section>
    </Panel>
  );
}

/** `/login/signed-out`: the sign-out is done. */
export function SignedOut() {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    title.current?.focus();
  }, []);
  return (
    <Panel>
      <section aria-labelledby="signed-out-heading" data-kind="signed_out" className={stack}>
        <Title id="signed-out-heading" ref={title}>
          {t("signout.done_title")}
        </Title>
        <a className={otherLink} href={LOGIN}>
          {t("signout.sign_in_again")}
        </a>
      </section>
    </Panel>
  );
}
