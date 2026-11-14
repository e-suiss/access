import { followColorScheme } from "@suiss/access-ui/lib/color-scheme";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { locale } from "./lib/i18n.js";
import "./styles.css";

document.documentElement.lang = locale;
followColorScheme();
// TN-131: React Aria's pressable rule is in styles.css; this marker stops its inline <style>
const pressable = document.createElement("meta");
pressable.id = "react-aria-pressable-style";
document.head.append(pressable);
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
