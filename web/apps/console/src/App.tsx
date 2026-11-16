// TN-128, IA-5, §8.17.4.1, OP-159 m.41 (b), m.42, m.43 (b): the console shell. Admin, Developer, Audit and
// Platform appear only when the eligibility check says the viewer can exercise one of their actions; without this browser's
// device key nothing is probed and nothing appears.
import { useCallback, useEffect, useState, type MouseEvent, type ReactElement } from "react";

import { Button } from "@access/ui/components/button";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  useSidebar,
} from "@access/ui/components/sidebar";

import { t, type Key } from "./i18n/index.js";
import { json, Problem, type SessionInfo } from "./lib/api.js";
import { find, type Instance } from "./lib/instance.js";
import {
  clearSignInStarted,
  consoleHref,
  knownEnvironments,
  lastEnvironment,
  rememberEnvironment,
  signInJustStarted,
  splitPath,
  startSignIn,
} from "./lib/paths.js";
import {
  type Screen,
  SCREENS,
  type Section,
  visibleScreens,
  visibleSections,
} from "./lib/sections.js";
import { platformEnvironments } from "./lib/environments.js";
import { EnvironmentSwitcher } from "./EnvironmentSwitcher.js";
import { Authority } from "./screens/Authority.js";
import { About, Profile, Sessions } from "./screens/Own.js";
import { SectionPage } from "./screens/Section.js";
import { NoEnvironment, OtherEnvironment, SignIn, SigningIn } from "./screens/SignIn.js";
import { useSignatureScreen } from "./SignatureDialog.js";
import { Busy, Failure } from "./ui.js";

const SECTIONS: ReadonlySet<string> = new Set<Section>(["admin", "developer", "audit", "platform"]);

type Route = "" | "profile" | "sessions" | "about" | Section;

const ROUTES: readonly Route[] = [
  "",
  "profile",
  "sessions",
  "about",
  "admin",
  "developer",
  "audit",
  "platform",
];

interface Where {
  readonly environment: string | undefined;
  readonly route: Route;
  readonly screen: Screen | undefined;
}

// OP-159 m.42 (a), TN-113
function routeOf(path: string): Where {
  const { environment, rest } = splitPath(path);
  const [head = "", sub] = rest.split("/", 2);
  if (!(ROUTES as readonly string[]).includes(head))
    return { environment, route: "", screen: undefined };
  const route = head as Route;
  const screens: readonly string[] = SECTIONS.has(route) ? SCREENS[route as Section] : [];
  const screen = sub !== undefined && screens.includes(sub) ? (sub as Screen) : undefined;
  return { environment, route, screen };
}

type State =
  | { readonly status: "loading" }
  | {
      readonly status: "signed-out";
      readonly reason: string | undefined;
      readonly signedOut: boolean;
    }
  | { readonly status: "unavailable" }
  | { readonly status: "signed-in"; readonly session: SessionInfo };

interface NavItem {
  readonly route: Route;
  readonly key: Key;
}

const NAV: readonly NavItem[] = [
  { route: "", key: "navAuthority" },
  { route: "admin", key: "navAdmin" },
  { route: "developer", key: "navDeveloper" },
  { route: "audit", key: "navAudit" },
  { route: "platform", key: "navPlatform" },
];

const OWN: readonly NavItem[] = [
  { route: "profile", key: "navProfile" },
  { route: "sessions", key: "navSessions" },
  { route: "about", key: "navAbout" },
];

/** The sidebar's toggle on narrow screens, where the sidebar is a sheet. */
function NavToggle(): ReactElement {
  const { toggleSidebar } = useSidebar();
  return (
    <Button
      variant="ghost"
      size="icon-sm"
      className="md:hidden"
      aria-label={t("navLabel")}
      onClick={toggleSidebar}
    >
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden>
        <path d="M2 4h12M2 8h12M2 12h12" strokeLinecap="round" />
      </svg>
    </Button>
  );
}

function NavGroup({
  environment,
  items,
  current,
  go,
  onNavigate,
}: {
  readonly environment: string;
  readonly items: readonly NavItem[];
  readonly current: Route;
  readonly go: (r: string) => (e: MouseEvent<HTMLAnchorElement>) => void;
  readonly onNavigate: () => void;
}): ReactElement {
  return (
    <SidebarGroup>
      <SidebarGroupContent>
        <SidebarMenu>
          {items.map((n) => (
            <SidebarMenuItem key={n.route}>
              <SidebarMenuButton
                isActive={current === n.route}
                render={(p) => (
                  <a
                    {...p}
                    href={consoleHref(environment, n.route)}
                    aria-current={current === n.route ? "page" : undefined}
                    onClick={(e) => {
                      go(n.route)(e);
                      onNavigate();
                    }}
                  />
                )}
              >
                {t(n.key)}
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}

function Nav({
  environment,
  items,
  current,
  go,
}: {
  readonly environment: string;
  readonly items: readonly NavItem[];
  readonly current: Route;
  readonly go: (r: string) => (e: MouseEvent<HTMLAnchorElement>) => void;
}): ReactElement {
  const { setOpenMobile } = useSidebar();
  const close = () => {
    setOpenMobile(false);
  };
  return (
    <nav aria-label={t("navLabel")} className="flex flex-col">
      <NavGroup
        environment={environment}
        items={items}
        current={current}
        go={go}
        onNavigate={close}
      />
      <NavGroup
        environment={environment}
        items={OWN}
        current={current}
        go={go}
        onNavigate={close}
      />
    </nav>
  );
}

function Waiting(): ReactElement {
  return (
    <main id="main" className="mx-auto flex w-full max-w-md flex-col p-8">
      <Busy />
    </main>
  );
}

export function App(): ReactElement {
  const [state, setState] = useState<State>({ status: "loading" });
  const [where, setWhere] = useState<Where>(() => routeOf(location.pathname));
  const [instance, setInstance] = useState<Instance | undefined>(undefined);
  const [screens, setScreens] = useState<ReadonlySet<Screen>>(new Set());
  const [platform, setPlatform] = useState<readonly string[]>([]);
  const [confirm, signatureScreen] = useSignatureScreen();
  const [justStarted] = useState(signInJustStarted);

  const navigate = useCallback((path: string, replace = false) => {
    if (replace) history.replaceState(null, "", path);
    else history.pushState(null, "", path);
    setWhere(routeOf(path));
  }, []);

  // OP-159 m.42 (a), (b)
  const loadSession = useCallback(() => {
    json<SessionInfo>("/session").then(
      (session) => {
        rememberEnvironment(session.environment);
        clearSignInStarted();
        if (routeOf(location.pathname).environment === undefined) {
          navigate(consoleHref(session.environment), true);
        }
        setState({ status: "signed-in", session });
      },
      (e: unknown) => {
        if (e instanceof Problem && e.status === 401) {
          const last = lastEnvironment();
          if (routeOf(location.pathname).environment === undefined && last !== undefined) {
            navigate(consoleHref(last), true);
          }
          setState({ status: "signed-out", reason: e.reason, signedOut: false });
        } else {
          setState({ status: "unavailable" });
        }
      },
    );
  }, [navigate]);

  useEffect(loadSession, [loadSession]);

  useEffect(() => {
    const pop = () => {
      setWhere(routeOf(location.pathname));
    };
    addEventListener("popstate", pop);
    return () => {
      removeEventListener("popstate", pop);
    };
  }, []);

  const session = state.status === "signed-in" ? state.session : undefined;
  const environment =
    where.environment ?? (session === undefined ? lastEnvironment() : session.environment);
  const autoSignIn =
    state.status === "signed-out" &&
    environment !== undefined &&
    state.reason === undefined &&
    !state.signedOut &&
    !justStarted;

  // OP-159 m.42 (a)
  useEffect(() => {
    if (autoSignIn) startSignIn(environment);
  }, [autoSignIn, environment]);

  useEffect(() => {
    if (session === undefined) return;
    let active = true;
    void find(session.environment, session.account, session.instance).then((i) => {
      if (active) setInstance(i);
    });
    return () => {
      active = false;
    };
  }, [session]);

  useEffect(() => {
    if (session === undefined || instance === undefined) return;
    let active = true;
    void visibleScreens(instance, session.environment).then((s) => {
      if (active) setScreens(s);
    });
    return () => {
      active = false;
    };
  }, [session, instance]);

  // OP-159 m.43 (b), TN-119
  const platformViewer = instance !== undefined && visibleSections(screens).has("platform");
  useEffect(() => {
    if (!platformViewer) return;
    let active = true;
    void platformEnvironments(instance).then((r) => {
      if (active) setPlatform(r);
    });
    return () => {
      active = false;
    };
  }, [platformViewer, instance]);

  const go = (r: string) => (e: MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    navigate(consoleHref(session?.environment ?? "", r));
  };

  const signOut = () => {
    json("/sign-out", { method: "POST" }).then(
      () => {
        setState({ status: "signed-out", reason: undefined, signedOut: true });
      },
      () => {
        setState({ status: "unavailable" });
      },
    );
  };

  if (state.status === "loading") return <Waiting />;
  if (state.status === "unavailable") {
    return (
      <main id="main" className="mx-auto flex w-full max-w-md flex-col gap-4 p-8">
        <h1 className="text-2xl font-semibold tracking-tight">{t("brand")}</h1>
        <Failure>{t("unavailable")}</Failure>
      </main>
    );
  }
  if (state.status === "signed-out") {
    if (environment === undefined) return <NoEnvironment />;
    if (autoSignIn) return <SigningIn environment={environment} />;
    return <SignIn environment={environment} reason={state.reason} signedOut={state.signedOut} />;
  }

  const s = state.session;
  if (environment !== undefined && environment !== s.environment) {
    const wanted = environment;
    return (
      <OtherEnvironment
        current={s.environment}
        wanted={wanted}
        onGo={() => {
          navigate(consoleHref(s.environment));
        }}
        onSwitch={() => {
          json("/sign-out", { method: "POST" }).then(
            () => {
              startSignIn(wanted);
            },
            () => {
              setState({ status: "unavailable" });
            },
          );
        }}
      />
    );
  }
  const shownScreens: ReadonlySet<Screen> = instance === undefined ? new Set() : screens;
  const visible: ReadonlySet<Section> = visibleSections(shownScreens);
  const route = where.route;
  const shown = NAV.filter((n) => !SECTIONS.has(n.route) || visible.has(n.route as Section));
  const current: Route = SECTIONS.has(route) && !visible.has(route as Section) ? "" : route;

  let page: ReactElement;
  if (current === "profile") page = <Profile session={s} />;
  else if (current === "sessions") page = <Sessions onEnded={loadSession} />;
  else if (current === "about") page = <About />;
  else if (SECTIONS.has(current) && instance !== undefined)
    page = (
      <SectionPage
        section={current as Section}
        screen={where.screen}
        ctx={{ session: s, instance, confirm, screens: shownScreens }}
        go={go}
      />
    );
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
    <SidebarProvider>
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-background px-3 py-2 text-sm font-medium ring-3 ring-ring/50 focus:not-sr-only focus:fixed focus:start-4 focus:top-4"
      >
        {t("skipToContent")}
      </a>
      <Sidebar>
        <SidebarHeader>
          <p className="px-3 py-2 text-base font-semibold">{t("brand")}</p>
        </SidebarHeader>
        <SidebarContent>
          <Nav environment={s.environment} items={shown} current={current} go={go} />
        </SidebarContent>
      </Sidebar>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background px-4 md:px-8">
          <NavToggle />
          <p className="font-semibold md:hidden">{t("brand")}</p>
          <p className="ms-auto min-w-0 truncate text-sm">
            <span data-testid="who">{s.display_name}</span>
          </p>
          <EnvironmentSwitcher
            current={s.environment}
            platform={platformViewer ? platform : []}
            known={knownEnvironments()}
            onGo={(r) => {
              navigate(consoleHref(r));
            }}
          />
          <Button variant="outline" size="sm" onClick={signOut}>
            {t("signOut")}
          </Button>
        </header>
        {page}
      </div>
      {signatureScreen}
    </SidebarProvider>
  );
}
