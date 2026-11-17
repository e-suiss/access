// TN-128, IA-5, §8.17.4.1, OP-159 m.41 (b), m.42, m.43 (b), m.46 (d), (e): the console shell. Admin,
// Developer, Audit and Platform appear only when the eligibility check says the viewer can exercise
// one of their actions; without this browser's device key nothing is probed and nothing appears.

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
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, Navigate, Outlet, useMatches, useNavigate, useParams } from "@tanstack/react-router";
import { createContext, lazy, type ReactElement, Suspense, use, useEffect, useState } from "react";

import { EnvironmentSwitcher } from "./EnvironmentSwitcher.js";
import { type Key, t } from "./i18n/index.js";
import { b64url, type SessionInfo } from "./lib/api.js";
import { find, findIn, type Instance } from "./lib/instance.js";
import {
  isEnvironment,
  knownEnvironments,
  lastEnvironment,
  signInJustStarted,
  startSignIn,
} from "./lib/remember.js";
import { type Screen, type Section, screensQuery, visibleSections } from "./lib/sections.js";
import { reloadSession, sessionQuery, signOut } from "./lib/session.js";
import { type TenantEnvironment, tenantEnvironmentsQuery } from "./lib/tenant.js";
import { useSignatureScreen } from "./SignatureDialog.js";
import { Authority } from "./screens/Authority.js";
import { EnterEnvironment } from "./screens/EnterEnvironment.js";
import type { Ctx } from "./screens/parts.js";
import { NoEnvironment, OtherEnvironment, SignIn, SigningIn } from "./screens/SignIn.js";
import { TenantHome } from "./screens/TenantHome.js";
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
  /** The session as the viewed environment's pages see it: that environment, its domain. */
  readonly session: SessionInfo;
  readonly instance: Instance | undefined;
  readonly confirm: Ctx["confirm"];
  readonly screens: ReadonlySet<Screen>;
  readonly registered: (i: Instance) => void;
  // OP-159 m.47 (a)
  /** The tenant's environments when the viewed environment is its primary environment. */
  readonly tenant: readonly TenantEnvironment[] | undefined;
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

// OP-159 m.42 (a), (c), (f), m.47 (a)
/**
 * `/console/{slug}/…`: signs in to the environment; signed in, the environment's pages, or a note
 * that the session is another tenant's.
 */
export function EnvironmentShell(): ReactElement {
  const { environment } = useParams({ from: "/$environment" });
  const q = useQuery(sessionQuery);
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
  return <SignedIn session={s.session} environment={environment} />;
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

/**
 * Whether `environment` is one the session's primary environment administers (OP-159 m.47 (a),
 * (g)): `undefined` while that is not known yet.
 */
function administered(
  session: SessionInfo,
  environment: string,
  own: Instance | null | undefined,
  tenant: {
    readonly data: readonly TenantEnvironment[] | null | undefined;
    readonly isError: boolean;
  },
): boolean | undefined {
  if (environment === session.environment || session.environments.includes(environment)) {
    return true;
  }
  if (own === null || tenant.isError || tenant.data === null) return false;
  if (own === undefined || tenant.data === undefined) return undefined;
  return tenant.data.some((e) => e.slug === environment && e.kind === "standard");
}

function SignedIn({
  session,
  environment,
}: {
  readonly session: SessionInfo;
  readonly environment: string;
}): ReactElement {
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
  const ownKey = ["instance", session.environment, session.account, session.instance] as const;
  const found = useQuery({
    queryKey: ownKey,
    queryFn: async () =>
      (await find(session.environment, session.account, session.instance)) ?? null,
    staleTime: Number.POSITIVE_INFINITY,
  });
  const own = found.data;
  // OP-159 m.47 (a), (g), TN-142
  const tenantRead = useQuery(tenantEnvironmentsQuery(own ?? undefined, session.environment));
  const tenantList = tenantRead.data ?? undefined;
  const foreign = environment !== session.environment;
  const inKey = ["instance-in", environment, session.account, session.instance] as const;
  const foundIn = useQuery({
    queryKey: inKey,
    queryFn: async () => (await findIn(environment, session.account, session.instance)) ?? null,
    staleTime: Number.POSITIVE_INFINITY,
    enabled: foreign,
  });
  const allowed = administered(session, environment, own, tenantRead);
  const instance = foreign ? (foundIn.data ?? undefined) : (own ?? undefined);
  const view: SessionInfo = foreign
    ? {
        ...session,
        environment,
        domain: instance === undefined ? session.domain : b64url(instance.domain),
      }
    : session;
  const probed = useQuery(screensQuery(instance, environment, session.account));
  const screens: ReadonlySet<Screen> =
    instance === undefined ? new Set() : (probed.data ?? new Set());
  const visible = visibleSections(screens);
  const tenantSlugs = (tenantList ?? [])
    .filter((e) => e.kind === "standard")
    .map((e) => e.slug)
    .sort();

  const route = useRoute();
  const shown = NAV.filter((n) => !SECTIONS.has(n.route) || visible.has(n.route as Section));
  const current: Route = SECTIONS.has(route) && !visible.has(route as Section) ? "" : route;
  const go = (to: string) => {
    void navigate({ to: "/$environment", params: { environment: to } });
  };

  // OP-159 m.42 (c), m.47 (a): only another tenant's environment is another sign-in
  if (allowed === false) {
    return (
      <OtherEnvironment
        current={session.environment}
        wanted={environment}
        onGo={() => {
          go(session.environment);
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
  if (allowed === undefined || (foreign && foundIn.data === undefined)) return <Waiting />;

  const shell: Shell = {
    session: view,
    instance,
    confirm,
    screens,
    tenant: foreign || tenantList === undefined ? undefined : tenantList,
    registered: (i) => {
      client.setQueryData(foreign ? inKey : ownKey, i);
      void reloadSession(client);
    },
  };
  const entering = foreign && instance === undefined;

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
            <Nav environment={environment} items={shown} current={current} />
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
              current={environment}
              home={tenantList === undefined ? undefined : session.environment}
              tenant={tenantSlugs}
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
          {entering ? (
            <EnterEnvironment
              environment={environment}
              home={session.environment}
              account={session.account}
              session={own === null || own === undefined ? null : session.instance}
              confirm={confirm}
              onRegistered={shell.registered}
            />
          ) : (
            <Outlet />
          )}
        </div>
        {signatureScreen}
        {palette !== undefined && (
          <Suspense fallback={null}>
            <CommandPalette
              open={palette}
              onOpenChange={setPalette}
              environment={environment}
              screens={screens}
              tenant={tenantList === undefined ? [] : [session.environment, ...tenantSlugs]}
              known={known}
              onEnvironment={go}
            />
          </Suspense>
        )}
      </SidebarProvider>
    </ShellContext>
  );
}

/**
 * The environment's home: its authority and this browser's device Instance; in a primary
 * environment, the tenant's home (OP-159 m.47 (a)).
 */
export function AuthorityPage(): ReactElement {
  const s = useShell();
  if (s.instance !== undefined && s.tenant !== undefined) {
    return (
      <TenantHome
        ctx={{ session: s.session, instance: s.instance, confirm: s.confirm, screens: s.screens }}
        environments={s.tenant}
      />
    );
  }
  return (
    <Authority
      session={s.session}
      instance={s.instance}
      confirm={s.confirm}
      onRegistered={s.registered}
    />
  );
}
