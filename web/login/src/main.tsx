import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { followColorScheme } from "@suiss/access-ui/lib/color-scheme";

import { App } from "./App.js";
import { linkTheme } from "./Branding.js";
import { applyDocument, loadOverrides } from "./i18n.js";
import "./styles.css";

applyDocument();
linkTheme();
followColorScheme();
// TN-131: React Aria's pressable rule is in styles.css; this marker stops its inline <style>
const pressable = document.createElement("meta");
pressable.id = "react-aria-pressable-style";
document.head.append(pressable);
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
