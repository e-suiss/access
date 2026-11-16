// OP-159 m.47 (f), TN-89: an administrator's invitation at `/login/admin-invite/{token}#code=…`. The
// invitee proves the invited address, chooses a password and this browser makes its own key; the
// account becomes an administrator, never an owner, and adds a second step at the first sign-in.
import * as v from "valibot";

import { type Kind, Onboarding } from "./Onboarding.js";

// OP-159 m.46 (f)
const View = v.looseObject({
  tenant: v.string(),
  environment: v.string(),
  state: v.picklist(["pending", "proven", "accepted", "superseded", "expired"]),
});

const CLOSED: Readonly<Record<string, string>> = {
  accepted: "admin_invite.used",
  superseded: "admin_invite.used",
  expired: "admin_invite.expired",
};

const ADMIN_INVITE: Kind<typeof View> = {
  kind: "admin_invite",
  page: "admin-invite",
  api: "admin-invites",
  finish: "accept",
  purpose: "admin",
  view: View,
  read: (i) => {
    const closed = CLOSED[i.state];
    return closed === undefined ? { name: i.tenant } : { name: i.tenant, closed };
  },
  refusals: {
    "invite-expired": "admin_invite.expired",
    "invite-state": "admin_invite.used",
  },
};

export function AdminInvite() {
  return <Onboarding kind={ADMIN_INVITE} />;
}
