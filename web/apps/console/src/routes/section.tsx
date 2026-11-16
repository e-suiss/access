// IA-5, OP-159 m.46 (e): a section's route. It shows the section only when the viewer may see one of
// its screens; otherwise the environment's home, as an unknown address does.
import type { ReactElement } from "react";

import type { Screen, Section } from "../lib/sections.js";
import { AuthorityPage, useCtx, useSectionVisible } from "../Shell.js";
import type { Ctx } from "../screens/parts.js";
import { SectionPage, screenOf } from "../screens/Section.js";

export function SectionRoute({
  section,
  screen,
  body,
}: {
  readonly section: Section;
  readonly screen: string | undefined;
  readonly body: (screen: Screen, ctx: Ctx) => ReactElement;
}): ReactElement {
  const ctx = useCtx();
  const visible = useSectionVisible(section);
  if (ctx === undefined || !visible) return <AuthorityPage />;
  return <SectionPage section={section} screen={screenOf(section, screen)} ctx={ctx} body={body} />;
}
