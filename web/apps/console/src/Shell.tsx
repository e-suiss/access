// TN-128, IA-5, §8.17.4.1, OP-159 m.41 (b), m.42, m.43 (b), m.46 (d), (e): the console shell. Admin,
// Developer, Audit and Platform appear only when the eligibility check says the viewer can exercise
// one of their actions; without this browser's device key nothing is probed and nothing appears.
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Navigate, Outlet, useMatches, useNavigate, useParams } from "@tanstack/react-router";
import { createContext, lazy, type ReactElement, Suspense, use, useEffect, useState } from "react";

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

import { EnvironmentSwitcher } from "./EnvironmentSwitcher.js";
import { type Key, t } from "./i18n/index.js";
import type { SessionInfo } from "./lib/api.js";
import { platformEnvironmentsQuery } from "./lib/environments.js";
import { find, type Instance } from "./lib/instance.js";
import {
  isEnvironment,
  knownEnvironments,
  lastEnvironment,
  signInJustStarted,
  startSignIn,
} from "./lib/remember.js";
import { type Screen, type Section, screensQuery, visibleSections } from "./lib/sections.js";
import { reloadSession, sessionQuery, signOut } from "./lib/session.js";
import { useSignatureScreen } from "./SignatureDialog.js";
import { Authority } from "./screens/Authority.js";
import type { Ctx } from "./screens/parts.js";
import { NoEnvironment, OtherEnvironment, SignIn, SigningIn } from "./screens/SignIn.js";
import { Busy, Failure } from "./ui.js";

const SECTIONS: ReadonlySet<string> = new Set<Section>(["admin", "developer", "audit", "platform"]);

type Route = "" | "profile" | "sessions" | "about" | Section;

const ROUTES: ReadonlySet<string> = new Set<Route>([
  "",
  "profile",
  "sessions",
  "about",
  "admin",
  "developer",
  "audit",
  "platform",
]);

/** The address of each page of an environment's console. */
const TO = {
  "": "/$environment",
  profile: "/$environment/profile",
  sessions: "/$environment/sessions",
  about: "/$environment/about",
  admin: "/$environment/admin/{-$screen}",
  developer: "/$environment/developer/{-$screen}",
  audit: "/$environment/audit/{-$screen}",
  platform: "/$environment/platform/{-$screen}",
} as const satisfies Readonly<Record<Route, string>>;

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

// OP-159 m.46 (g): the palette loads the first time it opens
const CommandPalette = lazy(() =>
  import("./CommandPalette.js").then((m) => ({ default: m.CommandPalette })),
);

// OP-159 m.42 (f): read once, when the console opens
const justStarted = signInJustStarted();

/** What every page of a signed-in environment works with. */
interface Shell {
  readonly session: SessionInfo;
  readonly instance: Instance | undefined;
  readonly confirm: Ctx["confirm"];
  readonly screens: ReadonlySet<Screen>;
  readonly registered: (i: Instance) => void;
}

const ShellContext = createContext<Shell | undefined>(undefined);

export function useShell(): Shell {
  const s = use(ShellContext);
  if (s === undefined) throw new Error("outside the console shell");
  return s;
}

/** A section screen's context, when this browser has its device Instance. */
export function useCtx(): Ctx | undefined {
  const s = useShell();
  if (s.instance === undefined) return undefined;
  return { session: s.session, instance: s.instance, confirm: s.confirm, screens: s.screens };
}

/** Whether `section` has a screen the viewer may see. */
export function useSectionVisible(section: Section): boolean {
  const s = useShell();
  return s.instance !== undefined && visibleSections(s.screens).has(section);
}

function Waiting(): ReactElement {
  return (
    <main id="main" className="mx-auto flex w-full max-w-md flex-col p-8">
      <Busy />
    </main>
  );
}

function Unavailable(): ReactElement {
  return (
    <main id="main" className="mx-auto flex w-full max-w-md flex-col gap-4 p-8">
      <h1 className="text-2xl font-semibold tracking-tight">{t("brand")}</h1>
      <Failure>{t("unavailable")}</Failure>
    </main>
  );
}

// OP-159 m.42 (b)
/** The bare `/console`: the session's environment, else the last one, else how to find yours. */
export function Home(): ReactElement {
  const q = useQuery(sessionQuery);
  if (q.data === undefined) return <Waiting />;
  const s = q.data;
  if (s.status === "unavailable") return <Unavailable />;
  const go = s.status === "signed-in" ? s.session.environment : lastEnvironment();
  if (go === undefined) return <NoEnvironment />;
  return <Navigate to="/$environment" params={{ environment: go }} replace />;
}

// OP-159 m.42 (a), (c), (f)
/** `/console/{slug}/…`: signs in to the environment, or notes the session is another one's. */
export function EnvironmentShell(): ReactElement {
  const { environment } = useParams({ from: "/$environment" });
  const q = useQuery(sessionQuery);
  const client = useQueryClient();
  const navigate = useNavigate();
  const valid = isEnvironment(environment);
  const s = q.data;
  const autoSignIn =
    valid && s?.status === "signed-out" && s.reason === undefined && !s.signedOut && !justStarted;

  useEffect(() => {
    if (autoSignIn) startSignIn(environment);
  }, [autoSignIn, environment]);

  if (!valid) return <Home />;
  if (s === undefined) return <Waiting />;
  if (s.status === "unavailable") return <Unavailable />;
  if (s.status === "signed-out") {
    if (autoSignIn) return <SigningIn environment={environment} />;
    return <SignIn environment={environment} reason={s.reason} signedOut={s.signedOut} />;
  }
  const session = s.session;
  if (environment !== session.environment) {
    return (
      <OtherEnvironment
        current={session.environment}
        wanted={environment}
        onGo={() => {
          void navigate({ to: "/$environment", params: { environment: session.environment } });
        }}
        onSwitch={() => {
          void signOut(client).then(() => {
            if (client.getQueryData(sessionQuery.queryKey)?.status === "signed-out") {
              startSignIn(environment);
            }
          });
        }}
      />
    );
  }
  return <SignedIn session={session} />;
}

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
  onNavigate,
}: {
  readonly environment: string;
  readonly items: readonly NavItem[];
  readonly current: Route;
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
                  <Link
                    {...p}
                    to={TO[n.route]}
                    params={{ environment }}
                    activeOptions={{ exact: n.route === "" }}
                    aria-current={current === n.route ? "page" : undefined}
                    onClick={onNavigate}
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
}: {
  readonly environment: string;
  readonly items: readonly NavItem[];
  readonly current: Route;
}): ReactElement {
  const { setOpenMobile } = useSidebar();
  const close = () => {
    setOpenMobile(false);
  };
  return (
    <nav aria-label={t("navLabel")} className="flex flex-col">
      <NavGroup environment={environment} items={items} current={current} onNavigate={close} />
      <NavGroup environment={environment} items={OWN} current={current} onNavigate={close} />
    </nav>
  );
}

/** The page the address names, from the deepest matched route. */
function useRoute(): Route {
  const matches = useMatches();
  const id = matches.at(-1)?.routeId ?? "";
  const head = id.split("/")[2] ?? "";
  return ROUTES.has(head) ? (head as Route) : "";
}

function SignedIn({ session }: { readonly session: SessionInfo }): ReactElement {
  const client = useQueryClient();
  const navigate = useNavigate();
  const [confirm, signatureScreen] = useSignatureScreen();
  const [known] = useState(knownEnvironments);
  const [palette, setPalette] = useState<boolean | undefined>(undefined);
  useEffect(() => {
    const key = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey) && !e.altKey) {
        e.preventDefault();
        setPalette((o) => o !== true);
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
    };
  }, []);
  const found = useQuery({
    queryKey: ["instance", session.environment, session.account, session.instance] as const,
    queryFn: async () =>
      (await find(session.environment, session.account, session.instance)) ?? null,
    staleTime: Number.POSITIVE_INFINITY,
  });
  const instance = found.data ?? undefined;
  const probed = useQuery(screensQuery(instance, session.environment, session.account));
  const screens: ReadonlySet<Screen> =
    instance === undefined ? new Set() : (probed.data ?? new Set());
  const visible = visibleSections(screens);
  // OP-159 m.43 (b), TN-119
  const platformViewer = instance !== undefined && visible.has("platform");
  const listed = useQuery({
    ...platformEnvironmentsQuery(instance, session.environment),
    enabled: platformViewer,
  });
  const platform = platformViewer ? (listed.data ?? []) : [];

  const route = useRoute();
  const shown = NAV.filter((n) => !SECTIONS.has(n.route) || visible.has(n.route as Section));
  const current: Route = SECTIONS.has(route) && !visible.has(route as Section) ? "" : route;
  const go = (environment: string) => {
    void navigate({ to: "/$environment", params: { environment } });
  };

  const shell: Shell = {
    session,
    instance,
    confirm,
    screens,
    registered: (i) => {
      client.setQueryData(["instance", session.environment, session.account, session.instance], i);
      void reloadSession(client);
    },
  };

  return (
    <ShellContext value={shell}>
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
            <Nav environment={session.environment} items={shown} current={current} />
          </SidebarContent>
        </Sidebar>
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-10 flex h-14 items-center gap-3 border-b bg-background px-4 md:px-8">
            <NavToggle />
            <p className="font-semibold md:hidden">{t("brand")}</p>
            <p className="ms-auto min-w-0 truncate text-sm">
              <span data-testid="who">{session.display_name}</span>
            </p>
            <EnvironmentSwitcher
              current={session.environment}
              platform={platform}
              known={known}
              onGo={go}
            />
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void signOut(client);
              }}
            >
              {t("signOut")}
            </Button>
          </header>
          <Outlet />
        </div>
        {signatureScreen}
        {palette !== undefined && (
          <Suspense fallback={null}>
            <CommandPalette
              open={palette}
              onOpenChange={setPalette}
              environment={session.environment}
              screens={screens}
              platform={platform}
              known={known}
              onEnvironment={go}
            />
          </Suspense>
        )}
      </SidebarProvider>
    </ShellContext>
  );
}

/** The environment's home: its authority and this browser's device Instance. */
export function AuthorityPage(): ReactElement {
  const s = useShell();
  return (
    <Authority
      session={s.session}
      instance={s.instance}
      confirm={s.confirm}
      onRegistered={s.registered}
    />
  );
}
