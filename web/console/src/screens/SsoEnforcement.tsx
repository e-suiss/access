// TN-94, TN-134, X20, OP-155 m.3 (i): an organization's enterprise sign-in. The preview says what
// enforcing would end before anything changes, service accounts included; enforcing names the
// pending invitations' fate, with no default; lifting widens again. A setup link goes to the
// organization's IT administrator and is shown once. Each is one signed change.
import { useState, type ReactElement } from "react";

import { Badge } from "@suiss/access-ui/components/ui/badge";
import { Button } from "@suiss/access-ui/components/ui/button";
import { Field, FieldLabel, FieldLegend, FieldSet } from "@suiss/access-ui/components/ui/field";
import { Input } from "@suiss/access-ui/components/ui/input";

import { t } from "../i18n/index.js";
import { adminGet, change, type WriteResult } from "../lib/admin.js";
import { ACTIONS, CHOICE, CHOICE_LABEL, FORM, MONO, Notice } from "../ui.js";
import { type Ctx, Panel, Show, useLoad, useRun } from "./parts.js";

interface Preview {
  readonly enforced: boolean;
  readonly invitations?: string | null;
  readonly service_accounts: readonly string[];
  readonly pending_invitations: number;
  readonly totals: { readonly members: number };
}

type Fate = "cancel" | "redirect_to_sso";

interface Linked extends WriteResult {
  readonly setup_link?: string;
}

/** The SSO panel of organization `org` (its Party's base64url). */
export function SsoEnforcement({
  ctx,
  org,
}: {
  readonly ctx: Ctx;
  readonly org: string;
}): ReactElement {
  const realm = encodeURIComponent(ctx.session.realm);
  const base = `organizations/${encodeURIComponent(org)}`;
  const preview = useLoad(() =>
    adminGet<Preview>(ctx.instance, `realms/${realm}/${base}/sso-enforcement/preview`),
  );
  const [fate, setFate] = useState<Fate | undefined>(undefined);
  const [email, setEmail] = useState("");
  const [w, write] = useRun<Linked>();
  const send = (operation: string, path: string, body: Record<string, unknown>) => {
    write(() =>
      change(ctx.instance, ctx.confirm, ctx.session.realm, {
        operation,
        key: org,
        method: "POST",
        path: `${base}/${path}`,
        body,
      }),
    );
  };
  return (
    <Panel id="org-sso" title={t("ssoTitle")}>
      <Show l={preview}>
        {(p) => (
          <>
            <p className="flex items-center gap-2">
              {t("ssoState")}:{" "}
              <Badge variant={p.enforced ? "default" : "outline"} data-testid="sso-state">
                {p.enforced ? t("ssoEnforced") : t("ssoNotEnforced")}
              </Badge>
            </p>
            <p data-testid="sso-preview">
              {t("ssoPreview", { members: String(p.totals.members) })}
            </p>
            <p data-testid="sso-service-accounts">
              {t("ssoServiceAccounts", { n: String(p.service_accounts.length) })}
            </p>
            <p>{t("ssoPending", { n: String(p.pending_invitations) })}</p>
            {p.enforced ? (
              <div className={ACTIONS}>
                <Button
                  variant="outline"
                  onPress={() => {
                    send("liftOrganizationSso", "sso-enforcement/lift", {});
                  }}
                >
                  {t("ssoLift")}
                </Button>
              </div>
            ) : (
              <form
                className={FORM}
                onSubmit={(e) => {
                  e.preventDefault();
                  if (fate !== undefined)
                    send("enforceOrganizationSso", "sso-enforcement", { invitations: fate });
                }}
              >
                <FieldSet className="gap-2">
                  <FieldLegend variant="label" className="mb-1">
                    {t("ssoFate")}
                  </FieldLegend>
                  {(["cancel", "redirect_to_sso"] as const).map((f) => (
                    <label key={f} className={CHOICE_LABEL}>
                      <input
                        className={CHOICE}
                        type="radio"
                        name="sso-fate"
                        value={f}
                        checked={fate === f}
                        onChange={() => {
                          setFate(f);
                        }}
                      />{" "}
                      {f === "cancel" ? t("ssoFateCancel") : t("ssoFateRedirect")}
                    </label>
                  ))}
                </FieldSet>
                <div className={ACTIONS}>
                  <Button type="submit" isDisabled={fate === undefined}>
                    {t("ssoEnforce")}
                  </Button>
                </div>
              </form>
            )}
          </>
        )}
      </Show>
      <form
        className={`${FORM} border-t pt-4`}
        onSubmit={(e) => {
          e.preventDefault();
          send("createOrganizationSetupLink", "setup-links", email === "" ? {} : { email });
        }}
      >
        <h5 className="text-sm font-semibold">{t("ssoSetupLink")}</h5>
        <Field className="gap-2">
          <FieldLabel htmlFor={`sso-setup-email-${org}`} className="text-sm">
            {t("ssoSetupEmail")}
          </FieldLabel>
          <Input
            id={`sso-setup-email-${org}`}
            type="email"
            size="md"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
            }}
          />
        </Field>
        <div className={ACTIONS}>
          <Button type="submit" variant="outline">
            {t("ssoSetupSend")}
          </Button>
        </div>
      </form>
      <Show l={w}>
        {(r) => (
          <>
            <Notice role="status">{t("changeRecorded", { exercise: r.exercise_id })}</Notice>
            {r.setup_link !== undefined && (
              <p data-testid="sso-setup-link" className="text-sm">
                {t("ssoSetupShown")} <span className={MONO}>{r.setup_link}</span>
              </p>
            )}
          </>
        )}
      </Show>
    </Panel>
  );
}
