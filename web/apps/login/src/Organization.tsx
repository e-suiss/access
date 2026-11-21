// TN-177: a person in more than one organization chooses which one to continue with when the app
// asked for the organization scope. The choice is context for the app, never authority.

import { useEffect, useRef, useState } from "react";
import * as v from "valibot";
import { LOGIN } from "./base.js";
import { sameOrigin } from "./Consent.js";
import { follow, postJson } from "./http.js";
import { t } from "./i18n.js";
import { note, Panel, problem, stack, Title } from "./Layout.js";

const Preview = v.looseObject({
  app: v.string(),
  organizations: v.array(v.looseObject({ id: v.string(), name: v.string() })),
});

type Preview = Readonly<v.InferOutput<typeof Preview>>;

const Redirect = v.looseObject({ redirect_to: v.string() });

type State =
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly preview: Preview }
  | { readonly phase: "failed" };

export function Organization() {
  const returnTo = sameOrigin(new URL(window.location.href).searchParams.get("return_to"));
  const [state, setState] = useState<State>(
    returnTo === null ? { phase: "failed" } : { phase: "loading" },
  );
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (returnTo === null) return;
    void postJson("/v1/login/organization/preview", { return_to: returnTo }, Preview).then((a) => {
      if (a.ok) setState({ phase: "ready", preview: a.body });
      else if (a.status === 401)
        window.location.assign(`${LOGIN}?return_to=${encodeURIComponent(returnTo)}`);
      else setState({ phase: "failed" });
    });
  }, [returnTo]);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const choose = async (organization: string) => {
    if (returnTo === null) return;
    setBusy(true);
    const a = await postJson(
      "/v1/login/organization",
      { return_to: returnTo, organization },
      Redirect,
    );
    if (a.ok) {
      follow(a.body.redirect_to);
      return;
    }
    setBusy(false);
    setState({ phase: "failed" });
  };

  return (
    <Panel aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="organization-heading" data-kind="organization" className={stack}>
        <Title id="organization-heading" ref={title}>
          {t("page.organization_title")}
        </Title>
        {state.phase === "loading" && (
          <p role="status" className={note}>
            {t("page.loading")}
          </p>
        )}
        {state.phase === "ready" && (
          <>
            <p className={note}>{t("page.organization_body", { app: state.preview.app })}</p>
            <nav className="flex flex-col gap-2" aria-labelledby="organization-heading">
              {state.preview.organizations.map((o) => (
                <button
                  key={o.id}
                  type="button"
                  className="flex min-h-14 w-full items-center rounded-xl border border-border bg-card px-4 py-3 text-start font-medium outline-none hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
                  disabled={busy}
                  onClick={() => void choose(o.id)}
                  data-organization={o.id}
                >
                  {o.name}
                </button>
              ))}
            </nav>
          </>
        )}
        {state.phase === "failed" && (
          <p role="alert" className={problem}>
            {t("page.organization_failed")}
          </p>
        )}
      </section>
    </Panel>
  );
}
