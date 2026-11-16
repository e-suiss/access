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

/** TN-128, OP-159 m.42 (a): the sign-in of `environment`, offered when it does not start on its own. */
export function SignIn({
  environment,
  reason,
  signedOut,
}: {
  readonly environment: string;
  readonly reason: string | undefined;
  readonly signedOut: boolean;
}): ReactElement {
  const why = reason === undefined ? undefined : REASONS[reason];
  return (
    <Frame title={t("signInTitle")}>
      {why !== undefined && <Notice role="status">{t("signInEnded", { reason: t(why) })}</Notice>}
      {signedOut && <Notice role="status">{t("signedOutNote")}</Notice>}
      <p className="text-muted-foreground">{t("signInIntro", { environment })}</p>
      <Button
        size="lg"
        block
        onClick={() => {
          startSignIn(environment);
        }}
      >
        {t("signInAction", { environment })}
      </Button>
    </Frame>
  );
}

/** OP-159 m.42 (a): on the way to the environment's hosted login. */
export function SigningIn({ environment }: { readonly environment: string }): ReactElement {
  return (
    <Frame title={t("signInTitle")}>
      <p role="status" className="text-muted-foreground">
        {t("signInOpening", { environment })}
      </p>
    </Frame>
  );
}

/** OP-159 m.42 (b): no environment in the address and none remembered, so nothing to sign in to. */
export function NoEnvironment(): ReactElement {
  return (
    <Frame title={t("noEnvironmentTitle")}>
      <p className="text-muted-foreground">{t("noEnvironmentText")}</p>
      <p className={`${MONO} break-all`} data-testid="console-link-shape">
        {`${location.origin}${HOME}/<environment>`}
      </p>
    </Frame>
  );
}

/** OP-159 m.42 (c): signed in to `current` at the console address of `wanted`. */
export function OtherEnvironment({
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
    <Frame title={t("otherEnvironmentTitle")}>
      <Notice role="status">{t("otherEnvironmentNote", { current, wanted })}</Notice>
      <div className="flex flex-col gap-3">
        <Button size="lg" block onClick={onGo}>
          {t("otherEnvironmentGo", { current })}
        </Button>
        <Button size="lg" variant="outline" block onClick={onSwitch}>
          {t("otherEnvironmentSwitch", { wanted })}
        </Button>
      </div>
    </Frame>
  );
}
