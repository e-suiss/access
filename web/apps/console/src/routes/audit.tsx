// §8.17.4.1 S9, OP-159 m.46 (e): Audit and its screens, loaded with the route.
import { getRouteApi } from "@tanstack/react-router";
import type { ReactElement } from "react";

import type { Screen } from "../lib/sections.js";
import * as Au from "../screens/Audit.js";
import * as D from "../screens/Developer.js";
import { Planned } from "../screens/Planned.js";
import type { Ctx } from "../screens/parts.js";
import { Recovery } from "../screens/Recovery.js";
import { SectionRoute } from "./section.js";

const route = getRouteApi("/$environment/audit/{-$screen}");

function body(screen: Screen, ctx: Ctx): ReactElement {
  switch (screen) {
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
    case "recovery":
      return <Recovery ctx={ctx} />;
    default:
      return <Planned />;
  }
}

export function AuditSection(): ReactElement {
  const { screen } = route.useParams();
  return <SectionRoute section="audit" screen={screen} body={body} />;
}
