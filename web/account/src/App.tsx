// OP-153 m.3 (w): the realm's account shell. "Account" (S11) runs on the session cookie alone and
// holds no authority; "Authority" (S2, S4, S5, S6, Changes) reads and signs with this browser's
// device Instance. The realm's name is the brand; no Suiss shell is imposed (X40).
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
import { Privacy } from "./privacy/Privacy.js";
import { SignedOutReason, SignIns } from "./signins/index.js";

type Screen = "account" | Section | "merchants" | "payment" | "save-card";

const SCREENS: readonly Screen[] = ["account", "authority", "activity", "changes", "merchants"];

function screenOf(path: string): Screen {
  const rest = path.slice(PAGE.length).replace(/^\//, "");
  // OP-156 m.3 (v): the one-time payment is reached from the merchant's request, not the menu
  if (rest === "payment" || rest === "save-card") return rest;
  return SCREENS.find((s) => s === rest) ?? "account";
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

  if (loaded.kind === "loading") return <p role="status">{t("shell.loading")}</p>;
  if (loaded.kind === "failed") return <p role="alert">{t("shell.unavailable")}</p>;
  if (loaded.kind === "signed_out") {
    return (
      <main className="shell">
        <p data-testid="signed-out">{t("shell.signed_out")}</p>
        <SignedOutReason />
        <a href={`${FRONTEND}/login`}>{t("action.sign_in")}</a>
      </main>
    );
  }
  const session = loaded.session;
  return (
    <div className="shell">
      <header>
        <strong data-testid="brand">{session.realm}</strong>
        <nav aria-label={t("settings.title")}>
          {SCREENS.map((s) => (
            <a
              key={s}
              href={pathOf(s)}
              aria-current={screen === s ? "page" : undefined}
              onClick={(e) => {
                e.preventDefault();
                go(s);
              }}
            >
              {s === "account"
                ? t("nav.account")
                : s === "authority"
                  ? t("nav.authority")
                  : s === "merchants"
                    ? t("merchants.title")
                    : t(`hub.${s}`)}
            </a>
          ))}
        </nav>
      </header>
      <main>
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
        ) : screen === "payment" ? (
          <OneTimePaymentPage instance={instance} confirm={confirm} />
        ) : (
          <Hub instance={instance} section={screen} />
        )}
      </main>
      {dialog}
    </div>
  );
}
