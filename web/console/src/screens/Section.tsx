// IA-5, §8.17.4.1, Ek B 2995: one section and its screens. Only the screens the viewer can
// exercise are listed; "Sign-in settings" (realm configuration) is its own screen apart from
// authority administration, and billing is not part of the console.
import type { MouseEvent, ReactElement } from "react";

import { t, type Key } from "../i18n/index.js";
import { type Screen, SCREENS, type Section } from "../lib/sections.js";
import * as A from "./Admin.js";
import { Agents } from "./Agents.js";
import * as Au from "./Audit.js";
import * as D from "./Developer.js";
import * as O from "./Organizations.js";
import type { Ctx } from "./parts.js";
import { SignInSettings } from "./SignInSettings.js";
import { Export as SiemExport } from "./Export.js";
import { Ssh } from "./Ssh.js";

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
};

const SECTION_TITLE: Readonly<Record<Section, Key>> = {
  admin: "navAdmin",
  developer: "navDeveloper",
  audit: "navAudit",
};

const SECTION_INTRO: Readonly<Record<Section, Key>> = {
  admin: "sectionAdminIntro",
  developer: "sectionDeveloperIntro",
  audit: "sectionAuditIntro",
};

function body(screen: Screen, ctx: Ctx): ReactElement {
  switch (screen) {
    case "roles":
      return <A.Roles ctx={ctx} />;
    case "people":
      return <A.People ctx={ctx} />;
    case "sources":
      return <A.Sources ctx={ctx} />;
    case "restrictions":
      return <A.Restrictions />;
    case "protected":
      return <A.Protected />;
    case "offboarding":
      return <A.Offboarding ctx={ctx} />;
    case "domain":
      return <A.Domain ctx={ctx} />;
    case "changes":
      return <A.Changes ctx={ctx} />;
    case "history":
      return <A.History ctx={ctx} />;
    case "organizations":
      return <O.Organizations ctx={ctx} />;
    case "agents":
      return <Agents ctx={ctx} />;
    case "ssh":
      return <Ssh ctx={ctx} />;
    case "siem":
      return <SiemExport ctx={ctx} />;
    case "sign-in":
      return <SignInSettings ctx={ctx} />;
    case "schemas":
      return <D.Schemas ctx={ctx} />;
    case "integrations":
      return <D.Integrations ctx={ctx} />;
    case "lab":
      return <D.Lab ctx={ctx} />;
    case "logs":
      return <D.Logs ctx={ctx} />;
    case "records":
      return <Au.Records ctx={ctx} />;
    case "replay":
      return <D.Replay ctx={ctx} />;
    case "revocation":
      return <Au.Revocation ctx={ctx} />;
    case "unknown":
      return <Au.Unknown ctx={ctx} />;
    case "containment":
      return <Au.Containment ctx={ctx} />;

    case "export":
      return <Au.Export ctx={ctx} />;
  }
}

/** The screens of `section` the viewer may see, in the section's order. */
export function screensOf(section: Section, visible: ReadonlySet<Screen>): readonly Screen[] {
  return (SCREENS[section] as readonly Screen[]).filter((s) => visible.has(s));
}

export function SectionPage({
  section,
  screen,
  ctx,
  go,
}: {
  readonly section: Section;
  readonly screen: Screen | undefined;
  readonly ctx: Ctx;
  readonly go: (path: string) => (e: MouseEvent<HTMLAnchorElement>) => void;
}): ReactElement {
  const shown = screensOf(section, ctx.screens);
  const current = screen !== undefined && shown.includes(screen) ? screen : shown[0];
  return (
    <main id="main" tabIndex={-1}>
      <h1>{t(SECTION_TITLE[section])}</h1>
      <p className="hint">{t(SECTION_INTRO[section])}</p>
      <nav aria-label={t("sectionScreens")} className="subnav">
        <ul>
          {shown.map((s) => (
            <li key={s}>
              <a
                href={`/console/${section}/${s}`}
                aria-current={s === current ? "page" : undefined}
                onClick={go(`${section}/${s}`)}
              >
                {t(SCREEN_TITLE[s])}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      {current !== undefined && (
        <section aria-labelledby="screen-title" key={current}>
          <h2 id="screen-title">{t(SCREEN_TITLE[current])}</h2>
          {body(current, ctx)}
        </section>
      )}
    </main>
  );
}
