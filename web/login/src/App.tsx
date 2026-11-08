// CMP-15.6, TN-133, X40: the realm's hosted pages under /login, drawn from the node contract and
// the realm's Frontend API; the realm's own branding, no Suiss shell.
import { Branding } from "./Branding.js";
import { Consent } from "./Consent.js";
import { ErrorPage } from "./ErrorPage.js";
import { Invitation } from "./Invitation.js";
import { MagicLink } from "./MagicLink.js";
import { Recovery } from "./Recovery.js";
import { SignIn } from "./SignIn.js";

/** The page a location draws. */
export type Page = "sign_in" | "sign_up" | "consent" | "recovery" | "invitation" | "link" | "error";

export function pageOf(path: string, search: string): Page {
  const rest = path.replace(/^(\/realms\/[a-z0-9-]+)?\/login/, "").replace(/\/+$/, "");
  if (rest === "/recovery") return "recovery";
  if (rest === "/link") return "link";
  if (rest === "/error") return "error";
  if (rest === "/invitation" || rest.startsWith("/invitation/")) return "invitation";
  const reason = new URLSearchParams(search).get("reason");
  // OP-153 m.3 (z)
  if (reason === "share") return "consent";
  // §10.4.6, Ek B 4098
  if (reason === "create") return "sign_up";
  return "sign_in";
}

function Body({ page }: { readonly page: Page }) {
  switch (page) {
    case "sign_in":
      return <SignIn kind="login" />;
    case "sign_up":
      return <SignIn kind="registration" />;
    case "consent":
      return <Consent />;
    case "recovery":
      return <Recovery />;
    case "invitation":
      return <Invitation />;
    case "link":
      return <MagicLink />;
    case "error":
      return <ErrorPage />;
  }
}

export function App() {
  const page = pageOf(window.location.pathname, window.location.search);
  return (
    <main data-page={page}>
      <Branding />
      <Body page={page} />
    </main>
  );
}
