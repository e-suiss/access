// IA-5, §8.17.4.1, Ek B 2995: one section and its screens. Only the screens the viewer can
// exercise are listed; "Sign-in settings" (environment configuration) is its own screen apart from
// authority administration, and billing is not part of the console.
import { Link } from "@tanstack/react-router";
import type { ReactElement } from "react";

import { cn } from "@access/ui/lib/utils";

import { type Key, t } from "../i18n/index.js";
import { type Screen, SCREENS, type Section } from "../lib/sections.js";
import { Page } from "../ui.js";
import type { Ctx } from "./parts.js";

export const SCREEN_TITLE: Readonly<Record<Screen, Key>> = {
  roles: "screenRoles",
  people: "screenPeople",
  sources: "screenSources",
  restrictions: "screenRestrictions",
  protected: "screenProtected",
  offboarding: "screenOffboarding",
  domain: "screenDomain",
  changes: "screenChanges",
  history: "screenHistory",
  organizations: "screenOrganizations",
  agents: "screenAgents",
  ssh: "screenSsh",
  siem: "screenSiem",
  linux: "screenLinux",
  proxy: "screenProxy",
  hr: "screenHr",
  breakglass: "screenBreakglass",
  reviews: "screenReviews",
  support: "screenSupport",
  placement: "screenPlacement",
  durability: "screenDurability",
  ratelimits: "screenRateLimits",
  signing: "screenSigning",
  "sign-in": "screenSignIn",
  schemas: "screenSchemas",
  integrations: "screenIntegrations",
  lab: "screenLab",
  logs: "screenLogs",
  records: "screenRecords",
  replay: "screenReplay",
  revocation: "screenRevocation",
  unknown: "screenUnknown",
  containment: "screenContainment",
  export: "screenExport",
  recovery: "screenRecovery",
  tenants: "screenTenants",
  envs: "screenEnvironments",
  sandboxes: "screenSandboxes",
  operator: "screenOperator",
};

export const SECTION_TITLE: Readonly<Record<Section, Key>> = {
  admin: "navAdmin",
  developer: "navDeveloper",
  audit: "navAudit",
  platform: "navPlatform",
};

const SECTION_INTRO: Readonly<Record<Section, Key>> = {
  admin: "sectionAdminIntro",
  developer: "sectionDeveloperIntro",
  audit: "sectionAuditIntro",
  platform: "sectionPlatformIntro",
};

/** Each section's address, its screen the optional last part. */
export const SECTION_TO = {
  admin: "/$environment/admin/{-$screen}",
  developer: "/$environment/developer/{-$screen}",
  audit: "/$environment/audit/{-$screen}",
  platform: "/$environment/platform/{-$screen}",
} as const satisfies Readonly<Record<Section, string>>;

/** Whether `s` names a screen of `section`. */
export function screenOf(section: Section, s: string | undefined): Screen | undefined {
  return s !== undefined && (SCREENS[section] as readonly string[]).includes(s)
    ? (s as Screen)
    : undefined;
}

/** The screens of `section` the viewer may see, in the section's order. */
export function screensOf(section: Section, visible: ReadonlySet<Screen>): readonly Screen[] {
  return (SCREENS[section] as readonly Screen[]).filter((s) => visible.has(s));
}

export function SectionPage({
  section,
  screen,
  ctx,
  body,
}: {
  readonly section: Section;
  readonly screen: Screen | undefined;
  readonly ctx: Ctx;
  readonly body: (screen: Screen, ctx: Ctx) => ReactElement;
}): ReactElement {
  const shown = screensOf(section, ctx.screens);
  const current = screen !== undefined && shown.includes(screen) ? screen : shown[0];
  return (
    <Page title={t(SECTION_TITLE[section])} intro={t(SECTION_INTRO[section])}>
      <nav aria-label={t("sectionScreens")} className="-mx-1 overflow-x-auto">
        <ul className="flex flex-wrap gap-1 px-1 py-1">
          {shown.map((s) => (
            <li key={s}>
              <Link
                to={SECTION_TO[section]}
                params={{ environment: ctx.session.environment, screen: s }}
                aria-current={s === current ? "page" : undefined}
                className={cn(
                  "inline-flex h-8 items-center rounded-full px-3 text-sm whitespace-nowrap transition-colors outline-none hover:bg-accent focus-visible:ring-3 focus-visible:ring-ring/50",
                  s === current
                    ? "bg-primary/10 font-semibold text-[color-mix(in_oklab,var(--primary)_70%,var(--foreground))]"
                    : "text-muted-foreground hover:text-foreground",
                )}
              >
                {t(SCREEN_TITLE[s])}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      {current !== undefined && (
        <section aria-labelledby="screen-title" key={current} className="flex flex-col gap-6">
          <h2 id="screen-title" className="text-xl font-semibold tracking-tight">
            {t(SCREEN_TITLE[current])}
          </h2>
          {body(current, ctx)}
        </section>
      )}
    </Page>
  );
}
