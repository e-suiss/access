// OP-152 m.7 (d), §9.16.2 k.4, TN-42
import { useState, type ReactElement } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";

import { t } from "../i18n/index.js";
import { change, type WriteResult } from "../lib/admin.js";
import { ACTIONS, FORM, HINT, Notice } from "../ui.js";
import { type Ctx, Field, Panel, Show, useRun } from "./parts.js";

/** Links an upstream provider's subject to an account: one `idp.upstream.link` Exercise. */
export function UpstreamLink({ ctx }: { readonly ctx: Ctx }): ReactElement {
  const [upstream, setUpstream] = useState("");
  const [sub, setSub] = useState("");
  const [account, setAccount] = useState("");
  const [w, write] = useRun<WriteResult>();
  return (
    <Panel id="upstream-link" title={t("upstreamLinkTitle")}>
      <p className={HINT}>{t("upstreamLinkIntro")}</p>
      <form
        className={FORM}
        onSubmit={(e) => {
          e.preventDefault();
          write(() =>
            change(ctx.instance, ctx.confirm, ctx.session.realm, {
              operation: "linkUpstreamSubject",
              key: upstream,
              method: "POST",
              path: `upstream-idps/${encodeURIComponent(upstream)}/links`,
              body: { sub, account_id: account },
            }),
          );
        }}
      >
        <Field
          id="upstream-link-name"
          label={t("upstreamLinkProvider")}
          value={upstream}
          onChange={setUpstream}
        />
        <Field
          id="upstream-link-sub"
          label={t("upstreamLinkSubject")}
          value={sub}
          onChange={setSub}
        />
        <Field
          id="upstream-link-account"
          label={t("peopleAccount")}
          value={account}
          onChange={setAccount}
        />
        <div className={ACTIONS}>
          <Button type="submit" isDisabled={upstream === "" || sub === "" || account === ""}>
            {t("upstreamLinkSave")}
          </Button>
        </div>
      </form>
      <Show l={w}>
        {(r) => <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>}
      </Show>
    </Panel>
  );
}
