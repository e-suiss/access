// §8.17.4.1, OP-159 m.46 (e): Admin and its screens, loaded with the route.
import { getRouteApi } from "@tanstack/react-router";
import type { ReactElement } from "react";

import type { Screen } from "../lib/sections.js";
import * as A from "../screens/Admin.js";
import { Agents } from "../screens/Agents.js";
import { BreakGlass } from "../screens/BreakGlass.js";
import { Durability } from "../screens/Durability.js";
import { Export as SiemExport } from "../screens/Export.js";
import { Hr } from "../screens/Hr.js";
import { Linux } from "../screens/Linux.js";
import { Offboarding } from "../screens/Offboarding.js";
import * as O from "../screens/Organizations.js";
import { Placement } from "../screens/Placement.js";
import { Planned } from "../screens/Planned.js";
import { Proxies } from "../screens/Proxy.js";
import type { Ctx } from "../screens/parts.js";
import { RateLimits } from "../screens/RateLimits.js";
import { Reviews } from "../screens/Reviews.js";
import { SignInSettings } from "../screens/SignInSettings.js";
import { Signing } from "../screens/Signing.js";
import { Ssh } from "../screens/Ssh.js";
import { SectionRoute } from "./section.js";

const route = getRouteApi("/$environment/admin/{-$screen}");

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
      return <Offboarding ctx={ctx} />;
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
    case "linux":
      return <Linux ctx={ctx} />;
    case "proxy":
      return <Proxies ctx={ctx} />;
    case "hr":
      return <Hr ctx={ctx} />;
    case "breakglass":
      return <BreakGlass ctx={ctx} />;
    case "reviews":
      return <Reviews ctx={ctx} />;
    case "placement":
      return <Placement ctx={ctx} />;
    case "durability":
      return <Durability ctx={ctx} />;
    case "ratelimits":
      return <RateLimits ctx={ctx} />;
    case "signing":
      return <Signing ctx={ctx} />;
    case "sign-in":
      return <SignInSettings ctx={ctx} />;
    default:
      return <Planned />;
  }
}

export function AdminSection(): ReactElement {
  const { screen } = route.useParams();
  return <SectionRoute section="admin" screen={screen} body={body} />;
}
