// OP-159 m.41 (b), m.46 (e): Platform and its screens, loaded with the route.
import { getRouteApi } from "@tanstack/react-router";
import type { ReactElement } from "react";

import type { Screen } from "../lib/sections.js";
import { Planned } from "../screens/Planned.js";
import * as P from "../screens/Platform.js";
import type { Ctx } from "../screens/parts.js";
import { SectionRoute } from "./section.js";

const route = getRouteApi("/$environment/platform/{-$screen}");

function body(screen: Screen, ctx: Ctx): ReactElement {
  switch (screen) {
    case "tenants":
      return <P.Tenants ctx={ctx} />;
    case "envs":
      return <P.Environments ctx={ctx} />;
    case "sandboxes":
      return <P.Sandboxes ctx={ctx} />;
    case "operator":
      return <P.Operator ctx={ctx} />;
    default:
      return <Planned />;
  }
}

export function PlatformSection(): ReactElement {
  const { screen } = route.useParams();
  return <SectionRoute section="platform" screen={screen} body={body} />;
}
