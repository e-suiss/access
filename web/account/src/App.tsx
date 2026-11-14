// OP-153 m.3 (w): the realm's account shell. "Account" (S11) runs on the session cookie alone and
// holds no authority; "Authority" (S2, S4, S5, S6, Changes) reads and signs with this browser's
// device Instance. The realm's name is the brand; no Suiss shell is imposed (X40).
import { Alert } from "@suiss/access-ui/components/ui/alert";
import { buttonVariants } from "@suiss/access-ui/components/ui/button";
import { Card, CardContent } from "@suiss/access-ui/components/ui/card";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
} from "@suiss/access-ui/components/ui/sidebar";
import { useEffect, useState, type ReactElement } from "react";

import { AccountSettings } from "./account/index.js";
import { DeviceSetup } from "./hub/DeviceSetup.js";
import { Hub, type Section } from "./hub/Hub.js";
import { MerchantsPage } from "./merchants/Merchants.js";
import { SaveCardPage } from "./merchants/SaveCard.js";
import { OneTimePaymentPage } from "./payment/Payment.js";
import { useSignature } from "./hub/Sign.js";
import { call, FRONTEND, json, PAGE, Problem, type SessionInfo } from "./lib/api.js";
import { t } from "./lib/i18n.js";
import { find, type Instance } from "./lib/instance.js";
import { Loading } from "./lib/ui.js";
import { Privacy } from "./privacy/Privacy.js";
import { SignedOutReason, SignIns } from "./signins/index.js";
import { SupportPage } from "./support/Support.js";

type Screen = "account" | Section | "merchants" | "payment" | "save-card" | "support";

const SCREENS: readonly Screen[] = [
  "account",
  "authority",
  "activity",
  "changes",
  "merchants",
  "support",
];

function screenOf(path: string): Screen {
  const rest = path.slice(PAGE.length).replace(/^\//, "");
  // OP-156 m.3 (v): the one-time payment is reached from the merchant's request, not the menu
  if (rest === "payment" || rest === "save-card") return rest;
  return SCREENS.find((s) => s === rest) ?? "account";
}

function label(s: Screen): string {
  if (s === "account") return t("nav.account");
  if (s === "authority") return t("nav.authority");
  if (s === "merchants") return t("merchants.title");
  if (s === "support") return t("support.title");
  return t(`hub.${s}`);
}

function pathOf(s: Screen): string {
  return s === "account" ? PAGE : `${PAGE}/${s}`;
}

type Loaded =
  | { readonly kind: "loading" }
  | { readonly kind: "signed_out" }
  | { readonly kind: "failed" }
  | { readonly kind: "ready"; readonly session: SessionInfo };

export function App(): ReactElement {
  const [loaded, setLoaded] = useState<Loaded>({ kind: "loading" });
  const [instance, setInstance] = useState<Instance | undefined>(undefined);
  const [screen, setScreen] = useState<Screen>(screenOf(location.pathname));
  const { confirm, dialog } = useSignature();

  useEffect(() => {
    json<SessionInfo>(call("/session"))
      .then(async (session) => {
        setInstance(await find(session.realm, session.account, session.instance));
        setLoaded({ kind: "ready", session });
      })
      .catch((e: unknown) => {
        setLoaded({ kind: e instanceof Problem && e.status === 401 ? "signed_out" : "failed" });
      });
    const back = () => {
      setScreen(screenOf(location.pathname));
    };
    addEventListener("popstate", back);
    return () => {
      removeEventListener("popstate", back);
    };
  }, []);

  const go = (s: Screen) => {
    history.pushState(null, "", pathOf(s));
    setScreen(s);
  };

  if (loaded.kind === "loading") {
    return (
      <main className="mx-auto max-w-3xl p-6">
        <Loading status />
      </main>
    );
  }
  if (loaded.kind === "failed") {
    return (
      <main className="mx-auto max-w-3xl p-6">
        <Alert variant="destructive">{t("shell.unavailable")}</Alert>
      </main>
    );
  }
  if (loaded.kind === "signed_out") {
    return (
      <main className="flex min-h-svh items-center justify-center bg-muted p-4">
        <Card className="w-full max-w-sm">
          <CardContent className="flex flex-col gap-4">
            <p data-testid="signed-out" className="text-lg font-semibold">
              {t("shell.signed_out")}
            </p>
            <SignedOutReason />
            <a href={`${FRONTEND}/login`} className={buttonVariants({ block: true })}>
              {t("action.sign_in")}
            </a>
          </CardContent>
        </Card>
      </main>
    );
  }
  const session = loaded.session;
  return (
    <SidebarProvider className="flex-col md:flex-row">
      <Sidebar
        collapsible="none"
        className="w-full border-b md:sticky md:top-0 md:h-svh md:w-(--sidebar-width) md:border-e md:border-b-0"
      >
        <SidebarHeader className="px-4 pt-4">
          <strong data-testid="brand" className="text-lg font-semibold wrap-anywhere">
            {session.realm}
          </strong>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <nav aria-label={t("settings.title")}>
              <SidebarMenu className="flex-row flex-wrap md:flex-col">
                {SCREENS.map((s) => (
                  <SidebarMenuItem key={s} className="md:w-full">
                    <SidebarMenuButton
                      isActive={screen === s}
                      className="h-auto min-h-9"
                      render={(p) => (
                        <a
                          {...p}
                          href={pathOf(s)}
                          aria-current={screen === s ? "page" : undefined}
                          onClick={(e) => {
                            e.preventDefault();
                            go(s);
                          }}
                        >
                          {label(s)}
                        </a>
                      )}
                    />
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </nav>
          </SidebarGroup>
        </SidebarContent>
      </Sidebar>
      <SidebarInset>
        <div className="mx-auto flex w-full max-w-3xl flex-col gap-8 p-4 md:p-8">
          {screen === "account" ? (
            <>
              <AccountSettings />
              <SignIns />
              <Privacy />
            </>
          ) : instance === undefined ? (
            <DeviceSetup session={session} confirm={confirm} onReady={setInstance} />
          ) : screen === "merchants" ? (
            <MerchantsPage instance={instance} confirm={confirm} />
          ) : screen === "save-card" ? (
            <SaveCardPage instance={instance} confirm={confirm} />
          ) : screen === "support" ? (
            <SupportPage instance={instance} confirm={confirm} />
          ) : screen === "payment" ? (
            <OneTimePaymentPage instance={instance} confirm={confirm} />
          ) : (
            <Hub instance={instance} section={screen} />
          )}
        </div>
      </SidebarInset>
      {dialog}
    </SidebarProvider>
  );
}
