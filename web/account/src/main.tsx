import { prepareDocument } from "@suiss/access-ui/lib/document";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App.js";
import { locale } from "./lib/i18n.js";
import "./styles.css";

document.documentElement.lang = locale;
prepareDocument();
const root = document.getElementById("root");
if (root === null) {
  throw new Error("missing #root element");
}
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
