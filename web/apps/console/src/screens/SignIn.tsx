import type { ReactElement, ReactNode } from "react";

import { Button } from "@access/ui/components/button";
import { Card, CardContent, CardHeader } from "@access/ui/components/card";

import { t, type Key } from "../i18n/index.js";
import { HOME, startSignIn } from "../lib/paths.js";
import { MONO, Notice } from "../ui.js";

const REASONS: Readonly<Record<string, Key>> = {
  "idle-expired": "reasonIdle",
  expired: "reasonExpired",
  "binding-mismatch": "reasonNetwork",
  ended: "reasonEnded",
  revoked: "reasonRevoked",
};

function Frame({
  title,
  children,
}: {
  readonly title: string;
  readonly children: ReactNode;
}): ReactElement {
  return (
    <main
      id="main"
      tabIndex={-1}
      className="flex min-h-svh items-center justify-center bg-muted px-4 py-10 outline-none"
    >
      <Card className="w-full max-w-md">
        <CardHeader>
          <p className="text-sm font-semibold text-muted-foreground">{t("brand")}</p>
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">{children}</CardContent>
      </Card>
    </main>
  );
}

/** TN-128, OP-159 m.42 (a): the sign-in of `realm`, offered when it does not start on its own. */
export function SignIn({
  realm,
  reason,
  signedOut,
}: {
  readonly realm: string;
  readonly reason: string | undefined;
  readonly signedOut: boolean;
}): ReactElement {
  const why = reason === undefined ? undefined : REASONS[reason];
  return (
    <Frame title={t("signInTitle")}>
      {why !== undefined && <Notice role="status">{t("signInEnded", { reason: t(why) })}</Notice>}
      {signedOut && <Notice role="status">{t("signedOutNote")}</Notice>}
      <p className="text-muted-foreground">{t("signInIntro", { realm })}</p>
      <Button
        size="lg"
        block
        onClick={() => {
          startSignIn(realm);
        }}
      >
        {t("signInAction", { realm })}
      </Button>
    </Frame>
  );
}

/** OP-159 m.42 (a): on the way to the realm's hosted login. */
export function SigningIn({ realm }: { readonly realm: string }): ReactElement {
  return (
    <Frame title={t("signInTitle")}>
      <p role="status" className="text-muted-foreground">
        {t("signInOpening", { realm })}
      </p>
    </Frame>
  );
}

/** OP-159 m.42 (b): no realm in the address and none remembered, so nothing to sign in to. */
export function NoRealm(): ReactElement {
  return (
    <Frame title={t("noRealmTitle")}>
      <p className="text-muted-foreground">{t("noRealmText")}</p>
      <p className={`${MONO} break-all`} data-testid="console-link-shape">
        {`${location.origin}${HOME}/<realm>`}
      </p>
    </Frame>
  );
}

/** OP-159 m.42 (c): signed in to `current` at the console address of `wanted`. */
export function OtherRealm({
  current,
  wanted,
  onGo,
  onSwitch,
}: {
  readonly current: string;
  readonly wanted: string;
  readonly onGo: () => void;
  readonly onSwitch: () => void;
}): ReactElement {
  return (
    <Frame title={t("otherRealmTitle")}>
      <Notice role="status">{t("otherRealmNote", { current, wanted })}</Notice>
      <div className="flex flex-col gap-3">
        <Button size="lg" block onClick={onGo}>
          {t("otherRealmGo", { current })}
        </Button>
        <Button size="lg" variant="outline" block onClick={onSwitch}>
          {t("otherRealmSwitch", { wanted })}
        </Button>
      </div>
    </Frame>
  );
}
