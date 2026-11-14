// IA-5, OP-157 m.4 (a): the body of a screen its lane has not served yet; `sections.ts` never
// lists such a screen, so this shows only on a direct link.
import type { ReactElement } from "react";

import { t } from "../i18n/index.js";
import { Notice } from "../ui.js";

export function Planned(): ReactElement {
  return <Notice role="status">{t("screenPlanned")}</Notice>;
}
