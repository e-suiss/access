// TN-89, OP-153 m.3 (o): an invitation names the organization as plain text (attacker input:
// never a link or markup); opening it consumes nothing; joining is the signed-in person's POST,
// and an address domain the organization has not confirmed asks first (TN-89 (10)).
import { useEffect, useRef, useState, type SyntheticEvent } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import { Field, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { Input } from "@suiss/access-ui/components/ui/input";

import { LOGIN } from "./base.js";
import { getJson, postJson } from "./http.js";
import { t } from "./i18n.js";
import {
  inlineLink,
  note,
  outcome,
  Panel,
  primary,
  problem,
  stack,
  Title,
  warning,
} from "./Layout.js";

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

const organization = "text-lg font-semibold wrap-anywhere";

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
    <Panel aria-busy={state.phase === "loading" || busy}>
      <section aria-labelledby="invitation-heading" data-kind="invitation" className={stack}>
        <Title id="invitation-heading" ref={title}>
          {t("invitation.title")}
        </Title>
        {state.phase === "loading" && (
          <p role="status" className={note}>
            {t("page.loading")}
          </p>
        )}
        {state.phase === "ask_code" && (
          <form onSubmit={enter} className={stack}>
            <Field className="gap-2">
              <FieldLabel htmlFor="field-invitation_code" className="text-sm">
                {t("label.invitation_code")}
              </FieldLabel>
              <Input
                id="field-invitation_code"
                name="invitation_code"
                type="text"
                autoComplete="one-time-code"
                required
                maxLength={16}
                spellCheck={false}
                autoCapitalize="characters"
                className="font-mono tracking-widest"
              />
            </Field>
            <Button type="submit" {...primary}>
              {t("action.continue")}
            </Button>
          </form>
        )}
        {(state.phase === "ready" || state.phase === "sign_in") && (
          <>
            <p className={organization} data-testid="organization">
              {state.invite.organization.display_name}
            </p>
            {state.phase === "sign_in" && (
              <p role="alert" className={warning}>
                {t("page.invitation_sign_in")}{" "}
                <a className={inlineLink} href={LOGIN}>
                  {t("action.sign_in")}
                </a>
              </p>
            )}
            <Button {...primary} disabled={busy} onPress={() => void join(state.invite, false)}>
              {t("action.accept_invitation")}
            </Button>
          </>
        )}
        {state.phase === "confirm" && (
          <>
            <p className={organization} data-testid="organization">
              {state.invite.organization.display_name}
            </p>
            <p role="alert" className={warning}>
              {t("page.invitation_unconfirmed_domain", { domain: state.invite.invitee_domain })}
            </p>
            <Button {...primary} disabled={busy} onPress={() => void join(state.invite, true)}>
              {t("page.invitation_join_anyway")}
            </Button>
          </>
        )}
        {state.phase === "joined" && (
          <p role="status" className={outcome} data-testid="joined">
            {t("page.invitation_joined", { organization: state.organization.display_name })}
          </p>
        )}
        {state.phase === "refused" && (
          <p role="alert" className={problem}>
            {t(state.text)}
          </p>
        )}
      </section>
    </Panel>
  );
}
