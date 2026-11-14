// TN-128, IA-5, §8.17.4.1: the console shell. Admin, Developer and Audit appear only when the
// eligibility check says the viewer can exercise one of their actions; without this browser's
// device key nothing is probed and nothing appears.
import { useCallback, useEffect, useState, type MouseEvent, type ReactElement } from "react";

import { Button } from "@suiss/access-ui/components/ui/button";
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
} from "@suiss/access-ui/components/ui/sidebar";

import { t, type Key } from "./i18n/index.js";
import { json, Problem, type SessionInfo } from "./lib/api.js";
import { find, type Instance } from "./lib/instance.js";
import {
  type Screen,
  SCREENS,
  type Section,
  visibleScreens,
  visibleSections,
} from "./lib/sections.js";
import { Authority } from "./screens/Authority.js";
import { About, Profile, Sessions } from "./screens/Own.js";
import { SectionPage } from "./screens/Section.js";
import { SignIn } from "./screens/SignIn.js";
import { useSignatureScreen } from "./SignatureDialog.js";
import { Busy, Failure, MONO } from "./ui.js";

const BASE = "/console/";

// TN-113: a path has one spelling and a trailing slash is an empty segment, so the console's
// own page is `/console` and every screen is `/console/<route>`
const HOME = "/console";

function hrefOf(r: string): string {
  return r === "" ? HOME : `${BASE}${r}`;
}

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

interface Where {
  readonly route: Route;
  readonly screen: Screen | undefined;
}

function routeOf(path: string): Where {
  const r = path.startsWith(BASE) ? path.slice(BASE.length).replace(/\/$/, "") : "";
  const [head = "", sub] = r.split("/", 2);
  if (!(ROUTES as readonly string[]).includes(head)) return { route: "", screen: undefined };
  const route = head as Route;
  const screens: readonly string[] =
    route === "admin" || route === "developer" || route === "audit" ? SCREENS[route] : [];
  const screen = sub !== undefined && screens.includes(sub) ? (sub as Screen) : undefined;
  return { route, screen };
}

type State =
  | { readonly status: "loading" }
  | { readonly status: "signed-out"; readonly reason: string | undefined }
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
      onPress={toggleSidebar}
    >
      <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" aria-hidden>
        <path d="M2 4h12M2 8h12M2 12h12" strokeLinecap="round" />
      </svg>
    </Button>
  );
}

function NavGroup({
  items,
  current,
  go,
  onNavigate,
}: {
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
                    href={hrefOf(n.route)}
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
  items,
  current,
  go,
}: {
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
      <NavGroup items={items} current={current} go={go} onNavigate={close} />
      <NavGroup items={OWN} current={current} go={go} onNavigate={close} />
    </nav>
  );
}

const SECTIONS: ReadonlySet<Route> = new Set<Route>(["admin", "developer", "audit"]);

export function App(): ReactElement {
  const [state, setState] = useState<State>({ status: "loading" });
  const [where, setWhere] = useState<Where>(() => routeOf(location.pathname));
  const [instance, setInstance] = useState<Instance | undefined>(undefined);
  const [screens, setScreens] = useState<ReadonlySet<Screen>>(new Set());
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
      setWhere(routeOf(location.pathname));
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
    void visibleScreens(instance, session.realm).then((s) => {
      if (active) setScreens(s);
    });
    return () => {
      active = false;
    };
  }, [session, instance]);

  const go = (r: string) => (e: MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    history.pushState(null, "", hrefOf(r));
    setWhere(routeOf(hrefOf(r)));
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
      <main id="main" className="mx-auto flex w-full max-w-md flex-col p-8">
        <Busy />
      </main>
    );
  }
  if (state.status === "unavailable") {
    return (
      <main id="main" className="mx-auto flex w-full max-w-md flex-col gap-4 p-8">
        <h1 className="text-2xl font-semibold tracking-tight">{t("brand")}</h1>
        <Failure>{t("unavailable")}</Failure>
      </main>
    );
  }
  if (state.status === "signed-out") return <SignIn reason={state.reason} />;

  const s = state.session;
  const shownScreens: ReadonlySet<Screen> = instance === undefined ? new Set() : screens;
  const visible: ReadonlySet<Section> = visibleSections(shownScreens);
  const route = where.route;
  const shown = NAV.filter((n) => !SECTIONS.has(n.route) || visible.has(n.route as Section));
  const current: Route = SECTIONS.has(route) && !visible.has(route as Section) ? "" : route;

  let page: ReactElement;
  if (current === "profile") page = <Profile session={s} />;
  else if (current === "sessions") page = <Sessions onEnded={loadSession} />;
  else if (current === "about") page = <About />;
  else if (
    (current === "admin" || current === "developer" || current === "audit") &&
    instance !== undefined
  )
    page = (
      <SectionPage
        section={current}
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
          <Nav items={shown} current={current} go={go} />
        </SidebarContent>
      </Sidebar>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background px-4 md:px-8">
          <NavToggle />
          <p className="font-semibold md:hidden">{t("brand")}</p>
          <p className="ms-auto min-w-0 truncate text-sm">
            <span data-testid="who">{s.display_name}</span>
            <span className="text-muted-foreground"> · </span>
            <span className={`${MONO} text-muted-foreground`}>{s.realm}</span>
          </p>
          <Button variant="outline" size="sm" onPress={signOut}>
            {t("signOut")}
          </Button>
        </header>
        {page}
      </div>
      {signatureScreen}
    </SidebarProvider>
  );
}
