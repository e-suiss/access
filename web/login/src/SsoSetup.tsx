// TN-133, TN-134, OP-155 m.3 (i): the organization SSO setup portal behind a one-use, 72-hour
// link. The page is `<OrganizationSSO />` over the realm's setup API, the same component a
// tenant embeds. Reading the link spends nothing; the first step binds it to this browser; what
// the page saves is a connection draft that an owner of the organization still has to turn on.
import { useEffect, useState } from "react";

import { sso as client } from "@esuiss/access";
import { sso } from "@suiss/access-react";

import { REALM } from "./base.js";
import { maybe, t } from "./i18n.js";

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly view: client.SetupView; readonly note: string | null }
  | { readonly phase: "spent" }
  | { readonly phase: "finished"; readonly organization: string }
  | { readonly phase: "failed" };

function stateOf(r: client.Answer<client.SetupView>, note: string | null): State {
  if (r.ok) return { phase: "ready", view: r.body, note };
  return r.status === 404 || r.status === 410 ? { phase: "spent" } : { phase: "failed" };
}

export function SsoSetup() {
  const link = client.linkOf(window.location.pathname);
  const [state, setState] = useState<State>(
    link === null ? { phase: "spent" } : { phase: "loading" },
  );

  useEffect(() => {
    if (link === null) return;
    let live = true;
    void client.readSetup(REALM, link).then((r) => {
      if (live) setState(stateOf(r, null));
    });
    return () => {
      live = false;
    };
  }, [link]);

  async function load(note: string | null) {
    if (link === null) return;
    setState(stateOf(await client.readSetup(REALM, link), note));
  }

  async function submit(step: sso.OrganizationSetupStep) {
    if (link === null || state.phase !== "ready") return;
    const r = await client.submitSetup(REALM, link, step as client.SetupStep);
    if (!r.ok) {
      if (r.status === 410) setState({ phase: "spent" });
      else setState({ ...state, note: t("login.unavailable") });
      return;
    }
    if (step.step === "finish") {
      setState({ phase: "finished", organization: state.view.organization.display_name });
      return;
    }
    const signIn = r.body["sign_in"];
    if (step.step === "test" && typeof signIn === "string") {
      window.location.assign(signIn);
      return;
    }
    await load(t("sso_setup.test"));
  }

  switch (state.phase) {
    case "loading":
      return <p aria-busy="true" />;
    case "spent":
      return (
        <p role="alert" data-testid="expired">
          {t("sso_setup.link_expired")}
        </p>
      );
    case "failed":
      return <p role="alert">{t("login.unavailable")}</p>;
    case "finished":
      return (
        <p role="status" data-testid="finished">
          {t("sso_setup.done", { organization: state.organization })}
        </p>
      );
    case "ready":
      return (
        <>
          <sso.OrganizationSSO
            setup={state.view}
            format={(key, args) => maybe(key, args)}
            onSubmit={(step) => {
              void submit(step);
            }}
          />
          {state.note === null ? null : (
            <p role="status" data-testid="note">
              {state.note}
            </p>
          )}
        </>
      );
  }
}
