import type { ReactElement, SyntheticEvent } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent, CardHeader } from "@suiss/access-ui/components/ui/card";
import { Field, FieldDescription, FieldLabel } from "@suiss/access-ui/components/ui/field";
import { Input } from "@suiss/access-ui/components/ui/input";

import { t, type Key } from "../i18n/index.js";
import { API } from "../lib/api.js";
import { Notice } from "../ui.js";

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
    <main
      id="main"
      tabIndex={-1}
      className="flex min-h-svh items-center justify-center bg-muted px-4 py-10 outline-none"
    >
      <Card className="w-full max-w-md">
        <CardHeader>
          <p className="text-sm font-semibold text-muted-foreground">{t("brand")}</p>
          <h1 className="text-2xl font-semibold tracking-tight">{t("signInTitle")}</h1>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          {why !== undefined && (
            <Notice role="status">{t("signInEnded", { reason: t(why) })}</Notice>
          )}
          <p className="text-muted-foreground">{t("signInIntro")}</p>
          <form onSubmit={start} className="flex flex-col gap-6">
            <Field className="gap-2">
              <FieldLabel htmlFor="realm" className="text-sm">
                {t("realmLabel")}
              </FieldLabel>
              <Input
                id="realm"
                name="realm"
                required
                pattern="[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]"
                autoComplete="organization"
                aria-describedby="realm-hint"
              />
              <FieldDescription id="realm-hint">{t("realmHint")}</FieldDescription>
            </Field>
            <Button type="submit" size="lg" block>
              {t("signInAction")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
