// OP-153 m.4: sign-in methods and where you're signed in (S10, S11 credential parts) are lane
// N5's; this is the shell's slot for them.
import type { ReactElement } from "react";

import { t } from "../lib/i18n.js";

export function SignIns(): ReactElement {
  return (
    <section aria-label={t("settings.sign_ins")} data-testid="sign-ins">
      <h2>{t("settings.sign_in_methods")}</h2>
      <h2>{t("settings.sign_ins")}</h2>
    </section>
  );
}
