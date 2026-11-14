import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { followColorScheme } from "@suiss/access-ui/lib/color-scheme";

import { App } from "./App.js";
import { linkTheme } from "./Branding.js";
import { applyDocument, loadOverrides } from "./i18n.js";
import "./styles.css";

/** React Aria's press rule is in styles.css; the `<style>` element it would add is refused by the CSP. */
function claimPressStyle(): void {
  const marker = document.createElement("meta");
  marker.id = "react-aria-pressable-style";
  document.head.append(marker);
}

applyDocument();
linkTheme();
followColorScheme();
claimPressStyle();
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
const mount = root;
void loadOverrides().finally(() => {
  createRoot(mount).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
});
