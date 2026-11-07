// TN-128, IA-5, §8.17.4.1: the console shell. Admin, Developer and Audit appear only when the
// eligibility check says the viewer can exercise one of their actions; without this browser's
// device key nothing is probed and nothing appears.
import { useCallback, useEffect, useState, type MouseEvent, type ReactElement } from "react";

import { t, type Key } from "./i18n/index.js";
import { json, Problem, type SessionInfo } from "./lib/api.js";
import { find, type Instance } from "./lib/instance.js";
import { type Section, visibleSections } from "./lib/sections.js";
import { Authority } from "./screens/Authority.js";
import { About, Profile, Sessions } from "./screens/Own.js";
import { SignIn } from "./screens/SignIn.js";
import { useSignatureScreen } from "./SignatureDialog.js";

const BASE = "/console/";

type Route = "" | "profile" | "sessions" | "about" | Section;

const ROUTES: readonly Route[] = [
  "",
  "profile",
  "sessions",
  "about",
  "admin",
  "developer",
  "audit",
];

function routeOf(path: string): Route {
  const r = path.startsWith(BASE) ? path.slice(BASE.length).replace(/\/$/, "") : "";
  return (ROUTES as readonly string[]).includes(r) ? (r as Route) : "";
}

type State =
  | { readonly status: "loading" }
  | { readonly status: "signed-out"; readonly reason: string | undefined }
  | { readonly status: "unavailable" }
  | { readonly status: "signed-in"; readonly session: SessionInfo };

const NAV: readonly { readonly route: Route; readonly key: Key }[] = [
  { route: "", key: "navAuthority" },
  { route: "admin", key: "navAdmin" },
  { route: "developer", key: "navDeveloper" },
  { route: "audit", key: "navAudit" },
  { route: "profile", key: "navProfile" },
  { route: "sessions", key: "navSessions" },
  { route: "about", key: "navAbout" },
];

const SECTIONS: ReadonlySet<Route> = new Set<Route>(["admin", "developer", "audit"]);

function SectionPage({ section }: { readonly section: Section }): ReactElement {
  const key: Key =
    section === "admin" ? "navAdmin" : section === "developer" ? "navDeveloper" : "navAudit";
  return (
    <main id="main" tabIndex={-1}>
      <h1>{t(key)}</h1>
    </main>
  );
}

export function App(): ReactElement {
  const [state, setState] = useState<State>({ status: "loading" });
  const [route, setRoute] = useState<Route>(() => routeOf(location.pathname));
  const [instance, setInstance] = useState<Instance | undefined>(undefined);
  const [sections, setSections] = useState<ReadonlySet<Section>>(new Set());
  const [confirm, signatureScreen] = useSignatureScreen();

  const loadSession = useCallback(() => {
    json<SessionInfo>("/session").then(
      (session) => {
        setState({ status: "signed-in", session });
      },
      (e: unknown) => {
        if (e instanceof Problem && e.status === 401) {
          setState({ status: "signed-out", reason: e.reason });
        } else {
          setState({ status: "unavailable" });
        }
      },
    );
  }, []);

  useEffect(loadSession, [loadSession]);

  useEffect(() => {
    const pop = () => {
      setRoute(routeOf(location.pathname));
    };
    addEventListener("popstate", pop);
    return () => {
      removeEventListener("popstate", pop);
    };
  }, []);

  const session = state.status === "signed-in" ? state.session : undefined;

  useEffect(() => {
    if (session === undefined) return;
    let active = true;
    void find(session.realm, session.account, session.instance).then((i) => {
      if (active) setInstance(i);
    });
    return () => {
      active = false;
    };
  }, [session]);

  useEffect(() => {
    if (session === undefined || instance === undefined) return;
    let active = true;
    void visibleSections(session.account, session.realm).then((s) => {
      if (active) setSections(s);
    });
    return () => {
      active = false;
    };
  }, [session, instance]);

  const go = (r: Route) => (e: MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    history.pushState(null, "", `${BASE}${r}`);
    setRoute(r);
  };

  const signOut = () => {
    json("/sign-out", { method: "POST" }).then(
      () => {
        setState({ status: "signed-out", reason: undefined });
      },
      () => {
        setState({ status: "unavailable" });
      },
    );
  };

  if (state.status === "loading") {
    return (
      <main id="main" aria-busy="true">
        <p>{t("loading")}</p>
      </main>
    );
  }
  if (state.status === "unavailable") {
    return (
      <main id="main">
        <h1>{t("brand")}</h1>
        <p role="alert">{t("unavailable")}</p>
      </main>
    );
  }
  if (state.status === "signed-out") return <SignIn reason={state.reason} />;

  const s = state.session;
  const visible: ReadonlySet<Section> = instance === undefined ? new Set() : sections;
  const shown = NAV.filter((n) => !SECTIONS.has(n.route) || visible.has(n.route as Section));
  const current: Route = SECTIONS.has(route) && !visible.has(route as Section) ? "" : route;

  let page: ReactElement;
  if (current === "profile") page = <Profile session={s} />;
  else if (current === "sessions") page = <Sessions onEnded={loadSession} />;
  else if (current === "about") page = <About />;
  else if (current === "admin" || current === "developer" || current === "audit")
    page = <SectionPage section={current} />;
  else
    page = (
      <Authority
        session={s}
        instance={instance}
        confirm={confirm}
        onRegistered={(i) => {
          setInstance(i);
          loadSession();
        }}
      />
    );

  return (
    <>
      <a className="skip" href="#main">
        {t("skipToContent")}
      </a>
      <header>
        <p className="brand">{t("brand")}</p>
        <p className="who">
          <span data-testid="who">{s.display_name}</span> · <span className="mono">{s.realm}</span>
        </p>
        <button type="button" onClick={signOut}>
          {t("signOut")}
        </button>
      </header>
      <nav aria-label={t("navLabel")}>
        <ul>
          {shown.map((n) => (
            <li key={n.route}>
              <a
                href={`${BASE}${n.route}`}
                aria-current={current === n.route ? "page" : undefined}
                onClick={go(n.route)}
              >
                {t(n.key)}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      {page}
      {signatureScreen}
    </>
  );
}
