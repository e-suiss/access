// §8.17.4.1, OP-159 m.46 (e): Developer and its screens, loaded with the route.
import { getRouteApi } from "@tanstack/react-router";
import type { ReactElement } from "react";

import type { Screen } from "../lib/sections.js";
import * as D from "../screens/Developer.js";
import type { Ctx } from "../screens/parts.js";
import { Planned } from "../screens/Planned.js";
import { SectionRoute } from "./section.js";

const route = getRouteApi("/$environment/developer/{-$screen}");

function body(screen: Screen, ctx: Ctx): ReactElement {
  switch (screen) {
    case "schemas":
      return <D.Schemas ctx={ctx} />;
    case "integrations":
      return <D.Integrations ctx={ctx} />;
    case "lab":
      return <D.Lab ctx={ctx} />;
    case "logs":
      return <D.Logs ctx={ctx} />;
    default:
      return <Planned />;
  }
}

export function DeveloperSection(): ReactElement {
  const { screen } = route.useParams();
  return <SectionRoute section="developer" screen={screen} body={body} />;
}
