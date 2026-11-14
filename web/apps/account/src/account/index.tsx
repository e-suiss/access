// S11 (§8.5, X32, OP-153 m.3 (w)): the identity plane's own settings, on the session cookie
// alone and without authority: how this person signs in, the sign-ins linked to the account, the
// apps it shares details with and the accounts connected for agents.
import type { ReactElement } from "react";

import { t } from "../lib/i18n.js";
import { PageTitle } from "../lib/ui.js";
import { AgentAccounts } from "./AgentAccounts.js";
import { Approvers } from "./Approvers.js";
import { Handles } from "./Handles.js";
import { ConnectedApps, LinkedSignIns } from "./Linked.js";
import { SignInMethods } from "./Methods.js";

export function AccountSettings(): ReactElement {
  return (
    <section
      aria-labelledby="settings-heading"
      data-testid="account-settings"
      className="flex flex-col gap-6"
    >
      <PageTitle id="settings-heading">{t("settings.title")}</PageTitle>
      <SignInMethods />
      <Approvers />
      <Handles />
      <LinkedSignIns />
      <ConnectedApps />
      <AgentAccounts />
    </section>
  );
}
