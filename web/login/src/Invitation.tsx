// TN-89, OP-153 m.3 (o): an invitation names the organization as plain text (attacker input:
// never a link or markup); opening it consumes nothing; joining is the signed-in person's POST,
// and an address domain the organization has not confirmed asks first (TN-89 (10)).
import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import { LOGIN } from "./base.js";
import { getJson, postJson } from "./http.js";
import { t } from "./i18n.js";

interface Organization {
  readonly id: string;
  readonly display_name: string;
}

interface Invite {
  readonly organization: Organization;
  readonly invitee_domain: string;
}

type State =
  | { readonly phase: "ask_code" }
  | { readonly phase: "loading" }
  | { readonly phase: "ready"; readonly invite: Invite }
  | { readonly phase: "confirm"; readonly invite: Invite }
  | { readonly phase: "joined"; readonly organization: Organization }
  | { readonly phase: "sign_in"; readonly invite: Invite }
  | { readonly phase: "refused"; readonly text: string };

const refusals: Readonly<Record<string, string>> = {
  "invitation-gone": "invitation.expired",
  "invitation-mismatch": "page.invitation_mismatch",
  "already-member": "page.invitation_already_member",
  "inviter-not-authorized": "page.invitation_inviter_gone",
};

function codeOfPath(): string | null {
  const m = /\/login\/invitation\/([A-Za-z0-9_-]{1,128})\/?$/.exec(window.location.pathname);
  return m?.[1] ?? null;
}

function isInvite(body: unknown): body is Invite {
  const b = body as Partial<Invite> | null;
  return typeof b?.organization?.display_name === "string" && typeof b.invitee_domain === "string";
}

export function Invitation() {
  const [code, setCode] = useState<string | null>(codeOfPath);
  const [state, setState] = useState<State>(
    code === null ? { phase: "ask_code" } : { phase: "loading" },
  );
  const [busy, setBusy] = useState(false);
  const title = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (code === null) return;
    void getJson<Invite>(`/v1/invitations/${encodeURIComponent(code)}`).then((a) => {
      if (a.ok && isInvite(a.body)) setState({ phase: "ready", invite: a.body });
      else
        setState({
          phase: "refused",
          text: a.ok ? "error.access_owner" : (refusals[a.code] ?? "invitation.expired"),
        });
    });
  }, [code]);

  useEffect(() => {
    if (state.phase !== "loading") title.current?.focus();
  }, [state.phase]);

  const join = async (invite: Invite, confirm: boolean) => {
    if (code === null) return;
    setBusy(true);
    const a = await postJson<{ organization: Organization }>(
      `/v1/invitations/${encodeURIComponent(code)}`,
      confirm ? { confirm: true } : {},
    );
    setBusy(false);
    if (a.ok) setState({ phase: "joined", organization: a.body.organization });
    else if (a.code === "interstitial-required") setState({ phase: "confirm", invite });
    else if (a.status === 401) setState({ phase: "sign_in", invite });
    else setState({ phase: "refused", text: refusals[a.code] ?? "error.access_owner" });
  };

  const enter = (event: SyntheticEvent<HTMLFormElement>) => {
    event.preventDefault();
    const value = new FormData(event.currentTarget).get("invitation_code");
    if (typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value.trim())) {
      setState({ phase: "loading" });
      setCode(value.trim());
    }
  };

  return (
    <div className="card" aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="invitation-heading" data-kind="invitation">
        <h1 id="invitation-heading" ref={title} tabIndex={-1}>
          {t("invitation.title")}
        </h1>
        {state.phase === "loading" && <p role="status">{t("page.loading")}</p>}
        {state.phase === "ask_code" && (
          <form onSubmit={enter}>
            <div className="field">
              <label htmlFor="field-invitation_code">{t("label.invitation_code")}</label>
              <input
                id="field-invitation_code"
                name="invitation_code"
                type="text"
                autoComplete="one-time-code"
                required
                maxLength={16}
                spellCheck={false}
                autoCapitalize="characters"
              />
            </div>
            <button type="submit" className="primary">
              {t("action.continue")}
            </button>
          </form>
        )}
        {(state.phase === "ready" || state.phase === "sign_in") && (
          <>
            <p className="organization" data-testid="organization">
              {state.invite.organization.display_name}
            </p>
            {state.phase === "sign_in" && (
              <p role="alert">
                {t("page.invitation_sign_in")} <a href={LOGIN}>{t("action.sign_in")}</a>
              </p>
            )}
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void join(state.invite, false)}
            >
              {t("action.accept_invitation")}
            </button>
          </>
        )}
        {state.phase === "confirm" && (
          <>
            <p className="organization" data-testid="organization">
              {state.invite.organization.display_name}
            </p>
            <p role="alert">
              {t("page.invitation_unconfirmed_domain", { domain: state.invite.invitee_domain })}
            </p>
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => void join(state.invite, true)}
            >
              {t("page.invitation_join_anyway")}
            </button>
          </>
        )}
        {state.phase === "joined" && (
          <p role="status" data-testid="joined">
            {t("page.invitation_joined", { organization: state.organization.display_name })}
          </p>
        )}
        {state.phase === "refused" && <p role="alert">{t(state.text)}</p>}
      </section>
    </div>
  );
}
