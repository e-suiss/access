// OP-159 m.47 (c), TN-141: the founder's page at `/login/founding/{token}#code=…`. The founder proves
// the invited address, chooses a password and this browser makes the key whose Party becomes the
// founding root of the tenant's management environment; a second step is added at the first
// sign-in (TN-138).
import * as v from "valibot";

import { type Kind, Onboarding } from "./Onboarding.js";

// OP-159 m.46 (f)
const View = v.looseObject({
  display_name: v.string(),
  environment: v.looseObject({ slug: v.string(), kind: v.string() }),
  expires_at: v.string(),
  verified: v.boolean(),
  completed: v.boolean(),
});

const FOUNDING: Kind<typeof View> = {
  kind: "founding",
  page: "founding",
  api: "foundings",
  finish: "complete",
  purpose: "founder",
  view: View,
  read: (f) =>
    f.completed ? { name: f.display_name, closed: "founding.completed" } : { name: f.display_name },
  refusals: {
    "founding-expired": "founding.expired",
    "founding-state": "founding.completed",
  },
};

export function Founding() {
  return <Onboarding kind={FOUNDING} />;
}
