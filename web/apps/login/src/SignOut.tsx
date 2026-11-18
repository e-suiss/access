// TN-152, TN-153, OIDC RP-Initiated Logout §2, §5: the pages the end-session endpoint sends a
// browser to. A sign-out the client did not tie to this browser's session is confirmed first and
// then ends as the client asked; a finished one says so and offers a new sign-in. No page names
// an app.

import { Button } from "@access/ui/components/button";
import { useEffect, useRef, useState } from "react";
import * as v from "valibot";

import { ENVIRONMENT, LOGIN } from "./base.js";
import { Empty, follow, postJson } from "./http.js";
import { t } from "./i18n.js";
import { otherLink, Panel, primary, problem, quiet, stack, Title } from "./Layout.js";

const Preview = v.object({ cancel_to: v.nullable(v.string()) });

type Confirmation =
  | { readonly phase: "loading" }
  | { readonly phase: "ticket"; readonly ticket: string; readonly cancelTo: string | null }
  | { readonly phase: "expired" }
  | { readonly phase: "current" };

/** The ticket rides in the fragment, so it never reaches a server log or a referrer. */
function takeFragment(): string {
  const fragment = window.location.hash.replace(/^#/, "");
  if (fragment !== "") window.history.replaceState(null, "", window.location.pathname);
  return fragment;
}

/** `/login/sign-out`: the confirmation of a sign-out its client did not tie to this browser
 * (TN-153). With its ticket the sign-out ends as the client asked and goes back to it; staying
 * signed in goes back too. Without one only this browser's sign-in ends. */
export function SignOut() {
  const [fragment] = useState(takeFragment);
  const ticket = /^ticket=([A-Za-z0-9_-]{43})$/.exec(fragment)?.[1] ?? null;
  const [state, setState] = useState<Confirmation>(
    ticket !== null
      ? { phase: "loading" }
      : fragment === "expired"
        ? { phase: "expired" }
        : { phase: "current" },
  );
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    title.current?.focus();
  }, []);
  useEffect(() => {
    if (ticket === null) return;
    void postJson("/v1/login/sign-out/preview", { ticket }, Preview).then((a) => {
      setState(
        a.ok ? { phase: "ticket", ticket, cancelTo: a.body.cancel_to } : { phase: "expired" },
      );
    });
  }, [ticket]);
  const here = async () => {
    setBusy(true);
    const a = await postJson("/v1/sessions/current/sign-out", {}, Empty);
    if (a.ok || a.status === 401) {
      window.location.assign(`${LOGIN}/signed-out`);
      return;
    }
    setBusy(false);
    setFailed(true);
  };
  const stay = () => {
    const back = state.phase === "ticket" ? state.cancelTo : null;
    if (back === null) window.location.assign(`${ENVIRONMENT}/account`);
    else follow(back);
  };
  return (
    <Panel aria-busy={busy || state.phase === "loading"}>
      <section aria-labelledby="sign-out-heading" data-kind="sign_out" className={stack}>
        <Title id="sign-out-heading" ref={title}>
          {t("signout.confirm_title")}
        </Title>
        {state.phase === "expired" && (
          <p role="alert" className={problem} data-testid="sign-out-expired">
            {t("signout.expired")}
          </p>
        )}
        {failed && (
          <p role="alert" className={problem}>
            {t("login.unavailable")}
          </p>
        )}
        {state.phase === "ticket" ? (
          <Button
            {...primary}
            disabled={busy}
            onClick={() => {
              setBusy(true);
              window.location.assign(
                `${ENVIRONMENT}/end-session?logout_ticket=${encodeURIComponent(state.ticket)}`,
              );
            }}
          >
            {t("signout.confirm")}
          </Button>
        ) : (
          <Button
            {...primary}
            disabled={busy || state.phase === "loading"}
            onClick={() => void here()}
          >
            {t("signout.confirm")}
          </Button>
        )}
        <Button {...quiet} disabled={busy || state.phase === "loading"} onClick={stay}>
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
