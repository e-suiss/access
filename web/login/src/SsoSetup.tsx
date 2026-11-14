// TN-133, TN-134, OP-155 m.3 (i): the organization SSO setup portal behind a one-use, 72-hour
// link. The page is `<OrganizationSSO />` over the realm's setup API, the same component a
// tenant embeds. Reading the link spends nothing; the first step binds it to this browser; what
// the page saves is a connection draft that an owner of the organization still has to turn on.
import { useEffect, useState } from "react";

import { sso as client } from "@esuiss/access";
import { sso } from "@suiss/access-react";
import { cn } from "@suiss/access-ui/lib/utils";

import { REALM } from "./base.js";
import { maybe, t } from "./i18n.js";
import { note, outcome, Panel, problem } from "./Layout.js";

/** The embedded component's own markup, drawn in the suiss/ui look. */
const portal = cn(
  "max-w-xl",
  "[&_section]:flex [&_section]:flex-col [&_section]:gap-4 [&_form]:flex [&_form]:flex-col [&_form]:gap-4",
  "[&_h2]:text-2xl [&_h2]:font-semibold [&_h2]:tracking-tight [&_h3]:text-lg [&_h3]:font-semibold",
  "[&_label]:flex [&_label]:flex-col [&_label]:gap-2 [&_label]:text-sm [&_label]:font-semibold",
  "[&_fieldset]:flex [&_fieldset]:flex-col [&_fieldset]:gap-2 [&_legend]:mb-2 [&_legend]:text-sm [&_legend]:font-semibold",
  "[&_fieldset_label]:min-h-6 [&_fieldset_label]:flex-row [&_fieldset_label]:items-center [&_fieldset_label]:font-normal",
  "[&_input:not([type=radio])]:h-11 [&_input:not([type=radio])]:rounded-lg [&_input:not([type=radio])]:bg-secondary [&_input:not([type=radio])]:px-3 [&_input:not([type=radio])]:text-base [&_input:not([type=radio])]:font-normal",
  "[&_select]:h-11 [&_select]:rounded-lg [&_select]:bg-secondary [&_select]:px-3 [&_select]:text-base [&_select]:font-normal",
  "[&_input[type=radio]]:size-5 [&_input[type=radio]]:accent-primary",
  "[&_input]:outline-none [&_input:focus-visible]:ring-3 [&_input:focus-visible]:ring-ring/50 [&_select]:outline-none [&_select:focus-visible]:ring-3 [&_select:focus-visible]:ring-ring/50",
  "[&_ol]:flex [&_ol]:list-decimal [&_ol]:flex-col [&_ol]:gap-3 [&_ol]:ps-5 [&_ul]:list-disc [&_ul]:ps-5 [&_code]:font-mono [&_code]:text-sm [&_code]:wrap-anywhere",
  "[&_button]:h-11 [&_button]:w-full [&_button]:cursor-pointer [&_button]:rounded-lg [&_button]:bg-primary [&_button]:px-5 [&_button]:text-base [&_button]:text-primary-foreground [&_button]:outline-none [&_button:focus-visible]:ring-3 [&_button:focus-visible]:ring-ring/50 [&_button:disabled]:cursor-not-allowed [&_button:disabled]:opacity-50",
);

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
        <Panel>
          <p role="alert" className={problem} data-testid="expired">
            {t("sso_setup.link_expired")}
          </p>
        </Panel>
      );
    case "failed":
      return (
        <Panel>
          <p role="alert" className={problem}>
            {t("login.unavailable")}
          </p>
        </Panel>
      );
    case "finished":
      return (
        <Panel>
          <p role="status" className={outcome} data-testid="finished">
            {t("sso_setup.done", { organization: state.organization })}
          </p>
        </Panel>
      );
    case "ready":
      return (
        <Panel className={portal}>
          <sso.OrganizationSSO
            setup={state.view}
            format={(key, args) => maybe(key, args)}
            onSubmit={(step) => {
              void submit(step);
            }}
          />
          {state.note === null ? null : (
            <p role="status" className={note} data-testid="note">
              {state.note}
            </p>
          )}
        </Panel>
      );
  }
}
