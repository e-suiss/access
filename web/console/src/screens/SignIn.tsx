import type { ReactElement, SyntheticEvent } from "react";

import { t, type Key } from "../i18n/index.js";
import { API } from "../lib/api.js";

const REASONS: Readonly<Record<string, Key>> = {
  "idle-expired": "reasonIdle",
  expired: "reasonExpired",
  "binding-mismatch": "reasonNetwork",
  ended: "reasonEnded",
  revoked: "reasonRevoked",
};

// TN-128, OP-159 m.29: a navigation, not a form submission, since `form-action 'self'` also
// governs the redirect to the realm's hosted login on another origin
function start(event: SyntheticEvent<HTMLFormElement, SubmitEvent>): void {
  event.preventDefault();
  const realm = new FormData(event.currentTarget).get("realm");
  if (typeof realm !== "string") return;
  window.location.assign(`${API}/sign-in?realm=${encodeURIComponent(realm)}`);
}

// TN-128: the console session starts at the realm's hosted login and comes back here
export function SignIn({ reason }: { readonly reason: string | undefined }): ReactElement {
  const why = reason === undefined ? undefined : REASONS[reason];
  return (
    <main id="main" tabIndex={-1}>
      <h1>{t("signInTitle")}</h1>
      {why !== undefined && (
        <p role="status" className="notice">
          {t("signInEnded", { reason: t(why) })}
        </p>
      )}
      <p>{t("signInIntro")}</p>
      <form onSubmit={start} className="stack">
        <label htmlFor="realm">{t("realmLabel")}</label>
        <input
          id="realm"
          name="realm"
          required
          pattern="[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]"
          autoComplete="organization"
          aria-describedby="realm-hint"
        />
        <p id="realm-hint" className="hint">
          {t("realmHint")}
        </p>
        <button type="submit" className="primary">
          {t("signInAction")}
        </button>
      </form>
    </main>
  );
}
