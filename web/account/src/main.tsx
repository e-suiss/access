import { followColorScheme } from "@suiss/access-ui/lib/color-scheme";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { keepStylesInStylesheet } from "./lib/csp.js";
import { locale } from "./lib/i18n.js";
import "./styles.css";

document.documentElement.lang = locale;
followColorScheme();
keepStylesInStylesheet();
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
