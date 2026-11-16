// Ek B 3089, OP-159 m.46 (e): the viewer's own pages, loaded with their route.
import { useQueryClient } from "@tanstack/react-query";
import type { ReactElement } from "react";

import { reloadSession } from "../lib/session.js";
import { About, Profile, Sessions } from "../screens/Own.js";
import { useShell } from "../Shell.js";

export function ProfilePage(): ReactElement {
  return <Profile session={useShell().session} />;
}

export function SessionsPage(): ReactElement {
  const client = useQueryClient();
  return (
    <Sessions
      onEnded={() => {
        void reloadSession(client);
      }}
    />
  );
}

export function AboutPage(): ReactElement {
  return <About />;
}
