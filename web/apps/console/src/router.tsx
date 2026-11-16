// OP-159 m.42, m.46 (e), TN-113: the console's addresses as typed routes under `/console`. Its own
// page is `/console`; an environment's console is `/console/{slug}`, its pages
// `/console/{slug}/<route>` and a section's screens `/console/{slug}/<section>/<screen>`; no address
// ends in `/`. Sections load with their route. A new page is one more child of `environment`.
import {
  createRootRoute,
  createRoute,
  createRouter,
  lazyRouteComponent,
  Outlet,
} from "@tanstack/react-router";
import * as v from "valibot";

import { BASE } from "./lib/links.js";
import { AuthorityPage, EnvironmentShell, Home } from "./Shell.js";
import { Busy } from "./ui.js";

/** A filter kept in the address: text, or a number the address parser read as one. */
const filter = v.fallback(
  v.optional(v.pipe(v.union([v.string(), v.number()]), v.transform(String))),
  undefined,
);

// OP-159 m.46 (e)
/** Admin's filters: the party whose holdings are looked up. */
const AdminSearch = v.object({ party: filter });

/** Audit's filters: the record looked up or searched. */
const AuditSearch = v.object({
  position: filter,
  subject: filter,
  action: filter,
  resource: filter,
});

const root = createRootRoute({ component: Outlet });

const home = createRoute({ getParentRoute: () => root, path: "/", component: Home });

export const environment = createRoute({
  getParentRoute: () => root,
  path: "$environment",
  component: EnvironmentShell,
});

const authority = createRoute({
  getParentRoute: () => environment,
  path: "/",
  component: AuthorityPage,
});

const profile = createRoute({
  getParentRoute: () => environment,
  path: "profile",
  component: lazyRouteComponent(() => import("./routes/own.js"), "ProfilePage"),
});

const sessions = createRoute({
  getParentRoute: () => environment,
  path: "sessions",
  component: lazyRouteComponent(() => import("./routes/own.js"), "SessionsPage"),
});

const about = createRoute({
  getParentRoute: () => environment,
  path: "about",
  component: lazyRouteComponent(() => import("./routes/own.js"), "AboutPage"),
});

const admin = createRoute({
  getParentRoute: () => environment,
  path: "admin/{-$screen}",
  validateSearch: AdminSearch,
  component: lazyRouteComponent(() => import("./routes/admin.js"), "AdminSection"),
});

const developer = createRoute({
  getParentRoute: () => environment,
  path: "developer/{-$screen}",
  component: lazyRouteComponent(() => import("./routes/developer.js"), "DeveloperSection"),
});

const audit = createRoute({
  getParentRoute: () => environment,
  path: "audit/{-$screen}",
  validateSearch: AuditSearch,
  component: lazyRouteComponent(() => import("./routes/audit.js"), "AuditSection"),
});

const platform = createRoute({
  getParentRoute: () => environment,
  path: "platform/{-$screen}",
  component: lazyRouteComponent(() => import("./routes/platform.js"), "PlatformSection"),
});

// OP-159 m.42 (a): any other page of an environment is its home
const other = createRoute({
  getParentRoute: () => environment,
  path: "$",
  component: AuthorityPage,
});

const routeTree = root.addChildren([
  home,
  environment.addChildren([
    authority,
    profile,
    sessions,
    about,
    admin,
    developer,
    audit,
    platform,
    other,
  ]),
]);

export const router = createRouter({
  routeTree,
  basepath: BASE,
  trailingSlash: "never",
  defaultPendingComponent: Busy,
  defaultPendingMs: 300,
});

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
